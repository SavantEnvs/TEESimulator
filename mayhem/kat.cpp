// Known-answer tests for the host-compilable common/ code: the tjson reader, the control channel's
// base64 and message handlers, KeyMint name rendering and the redaction token. Built with normal
// flags (no sanitizers) and run by mayhem/test.sh, which checks the printed pass count.
#include <stdio.h>

#include "control_driver.h"
#include "km_names.h"
#include "redact.h"
#include "router_stub.h"

extern "C" const char *teesim_km_err_name(int32_t code);

static int g_pass = 0, g_fail = 0;

static void Check(const char *name, bool ok) {
  if (ok) {
    ++g_pass;
    printf("KAT PASS %s\n", name);
  } else {
    ++g_fail;
    printf("KAT FAIL %s\n", name);
  }
}

static bool Parse(const std::string &s, tjson::Value &v) { return tjson::parse(s.data(), s.size(), v); }

static void JsonTests() {
  tjson::Value v;
  Check("json.parse_ok", Parse(R"({"a":[1,2.5,"x",true,null],"b":{"c":20250805}})", v));
  Check("json.array_size", v.get("a") && v.get("a")->size() == 5);
  Check("json.array_int", v.get("a")->at(0).as_int() == 1);
  Check("json.array_double", v.get("a")->at(1).as_double() == 2.5);
  Check("json.array_string", v.get("a")->at(2).as_string() == "x");
  Check("json.array_bool", v.get("a")->at(3).as_bool());
  Check("json.array_null", v.get("a")->at(4).is_null());
  Check("json.nested_exact_int", v.get("b") && v.get("b")->get("c") &&
                                     v.get("b")->get("c")->as_int() == 20250805);
  Check("json.out_of_range_is_null", v.get("a")->at(99).is_null());
  Check("json.missing_key", v.get("zzz") == nullptr);
  Check("json.type_mismatch_default", v.get("a")->at(2).as_int(-7) == -7);

  tjson::Value big;
  Check("json.int64_max", Parse("9223372036854775807", big) && big.as_int() == INT64_MAX);
  tjson::Value neg;
  Check("json.negative", Parse("-42", neg) && neg.as_int() == -42);
  tjson::Value dup;
  Check("json.duplicate_key_last_wins",
        Parse(R"({"k":1,"k":2})", dup) && dup.get("k") && dup.get("k")->as_int() == 2);
  tjson::Value esc;
  Check("json.unicode_escape_utf8",
        Parse(R"("\u00e9\n\"")", esc) && esc.as_string() == "\xc3\xa9\n\"");

  tjson::Value bad;
  Check("json.reject_missing_value", !Parse(R"({"a":})", bad));
  Check("json.reject_truncated", !Parse(R"({"a":[1,2)", bad));
  Check("json.reject_trailing_garbage", !Parse("{} x", bad));
  Check("json.reject_empty", !Parse("", bad));
  Check("json.reject_single_quote", !Parse("{'a':1}", bad));
  Check("json.reject_deep_nesting", !Parse(std::string(100000, '['), bad));
  Check("json.reject_deep_nesting_balanced",
        !Parse(std::string(100000, '[') + std::string(100000, ']'), bad));
  Check("json.accept_shallow_nesting", Parse(std::string(20, '[') + std::string(20, ']'), bad));
}

static void Base64Tests() {
  std::vector<uint8_t> out;
  Check("b64.decode_hello", Base64Decode("aGVsbG8=", out) && std::string(out.begin(), out.end()) == "hello");
  Check("b64.decode_no_padding", Base64Decode("aGVsbG8", out) && std::string(out.begin(), out.end()) == "hello");
  Check("b64.decode_whitespace", Base64Decode("aGVs\nbG8=", out) && std::string(out.begin(), out.end()) == "hello");
  Check("b64.reject_bad_char", !Base64Decode("aGV$bG8=", out));
  Check("b64.decode_empty", Base64Decode("", out) && out.empty());
  const uint8_t raw[] = {0x00, 0xff, 0x10, 0x80, 0x7f};
  Check("b64.encode_known", Base64Encode(raw, sizeof(raw)) == "AP8QgH8=");
  Check("b64.encode_one_byte", Base64Encode(raw, 1) == "AA==");
  std::string enc = Base64Encode(raw, sizeof(raw));
  Check("b64.roundtrip", Base64Decode(enc, out) && out == std::vector<uint8_t>(raw, raw + sizeof(raw)));
}

static std::string Dump(const std::vector<std::string> &frames) {
  std::string s;
  for (const auto &f : frames) s += f + "\n";
  return s;
}

static void ControlTests() {
  std::vector<std::string> frames;
  std::string reply = RunConnection(Frame(R"({"type":"ping","epoch":7})"));
  Check("ctl.frames_split", SplitFrames(reply, frames) && frames.size() == 2);
  Check("ctl.hello", frames.size() > 0 &&
                         frames[0].find("\"type\":\"hello\"") != std::string::npos &&
                         frames[0].find("\"hook\":\"mayhem-stub\"") != std::string::npos &&
                         frames[0].find("\"protocol\":1") != std::string::npos);
  Check("ctl.ping_pong", frames.size() > 1 && frames[1] == R"({"type":"pong","epoch":7})");

  frames.clear();
  reply = RunConnection(Frame(R"({"type":"getUsage"})"));
  SplitFrames(reply, frames);
  Check("ctl.get_usage", frames.size() == 2 &&
                             frames[1] == R"({"type":"usage","apps":[{"uid":1000,"count":2}],"rkpReassert":[]})");

  const std::string cfg = R"({"type":"config","epoch":42,"redactSalt":"c2FsdA==",
    "bootInfo":{"verifiedBootKey":"AAEC","verifiedBootHash":"AAECAwQ=","moduleHash":"/w==",
                "deviceLocked":false,"verifiedBootState":2,"strongBoxAvailable":true,
                "attestVersionTee":200,"attestVersionStrongBox":100},
    "rkpDeleted":["remote_provisioning.tee.rkp_only", 5, ""],
    "profiles":[
      {"id":"p1","mode":"patch","keyboxB64":"aGk=","securityLevel":2,"osVersion":140000,
       "packages":["com.a","com.b"],"packageUsers":[10],"uids":[1010,1011],"uidPackages":["com.a"],
       "deviceIds":{"brand":"google","model":"pixel"}},
      {"id":"bad"},
      {"id":"p3","keyboxB64":"!!!"}]})";
  frames.clear();
  reply = RunConnection(Frame(cfg));
  SplitFrames(reply, frames);
  Check("ctl.config_ack", frames.size() == 2 &&
                              frames[1] == R"({"type":"ack","epoch":42,"ok":true,"profilesApplied":1,"profilesFailed":2})");
  const mstub::State &st = mstub::g_state;
  Check("ctl.config_committed", st.began && st.committed && st.epoch == 42);
  Check("ctl.config_bootinfo", !st.locked && st.boot_state == 2 && st.attest_tee == 200 &&
                                   st.attest_sb == 100 && st.vb_key_len == 3 &&
                                   st.vb_hash_len == 5 && st.module_hash_len == 1);
  Check("ctl.config_rkp_deleted", st.rkp_deleted.size() == 1 &&
                                      st.rkp_deleted[0] == "remote_provisioning.tee.rkp_only");
  Check("ctl.config_profile_count", st.profiles.size() == 2);
  if (st.profiles.size() == 2) {
    const mstub::Profile &p = st.profiles[0];
    Check("ctl.profile_fields", p.id == "p1" && p.mode == "patch" && p.keybox_len == 2 &&
                                    p.security_level == 2 && p.os_version == 140000);
    Check("ctl.profile_packages", p.packages.size() == 2 && p.packages[1] == "com.b" &&
                                      p.package_users[0] == 10 && p.package_users[1] == 0);
    Check("ctl.profile_uids", p.uids.size() == 2 && p.uids[1] == 1011 && p.uid_packages[0] == "com.a" &&
                                  p.uid_packages[1] == "");
    Check("ctl.profile_device_ids", p.has_ids && p.brand == "google");
    Check("ctl.profile_without_ids", !st.profiles[1].has_ids && st.profiles[1].id == "bad");
  } else {
    Check("ctl.profile_fields", false);
  }

  frames.clear();
  reply = RunConnection(Frame(R"({"type":"resign","profile":"p1","leafB64":"AAEC"})") +
                        Frame(R"({"type":"resign","profile":"nope","leafB64":"AAEC"})") +
                        Frame(R"({"type":"resign","profile":"p1"})"));
  SplitFrames(reply, frames);
  Check("ctl.resign_ok", frames.size() == 4 && frames[1] == R"({"type":"resigned","ok":true,"chainB64":["MAEA"]})");
  Check("ctl.resign_unknown_profile", frames.size() == 4 && frames[2] == R"({"type":"resigned","ok":false,"chainB64":[]})");
  Check("ctl.resign_missing_leaf", frames.size() == 4 && frames[3] == R"({"type":"resigned","ok":false,"chainB64":[]})");

  frames.clear();
  reply = RunConnection(Frame("not json") + Frame(R"({"type":"mystery"})") +
                        Frame(R"({"type":"ping","epoch":1})"));
  SplitFrames(reply, frames);
  Check("ctl.bad_frames_skipped", frames.size() == 2 && frames[1] == R"({"type":"pong","epoch":1})");

  frames.clear();
  const std::string zero_len = std::string("\0\0\0\0", 4) + Frame(R"({"type":"ping","epoch":9})");
  reply = RunConnection(zero_len);
  SplitFrames(reply, frames);
  Check("ctl.zero_length_frame_ends_session", frames.size() == 1);
  Check("ctl.dump_nonempty", !Dump(frames).empty());
}

static void KmNameTests() {
  KmParam ps[6] = {};
  ps[0] = {0x20000001u, 2, nullptr, 0};   // purpose SIGN
  ps[1] = {0x10000002u, 3, nullptr, 0};   // algorithm EC
  ps[2] = {0x20000001u, 3, nullptr, 0};   // purpose VERIFY (grouped under the first)
  ps[3] = {0x30000003u, 256, nullptr, 0}; // key_size
  ps[4] = {0x700001f7u, 1, nullptr, 0};   // no_auth_required
  ps[5] = {0x20000005u, 4, nullptr, 0};   // digest SHA_2_256
  Check("km.describe_grouped",
        KmDescribeParams(ps, 6) ==
            "{purpose=SIGN|VERIFY algorithm=EC key_size=256 no_auth_required digest=SHA_2_256}");
  KmParam d = {0x600002bdu, 0, nullptr, 0};  // creation_datetime
  Check("km.describe_epoch_date", KmDescribeParams(&d, 1) == "{creation_datetime=1970-01-01T00:00:00Z}");
  KmParam d2 = {0x600002bdu, 1700000000000LL, nullptr, 0};
  Check("km.describe_date", KmDescribeParams(&d2, 1) == "{creation_datetime=2023-11-14T22:13:20Z}");
  KmParam a = {0x100001f8u, 3, nullptr, 0};  // user_auth_type PASSWORD|FINGERPRINT
  Check("km.describe_auth_type_mask", KmDescribeParams(&a, 1) == "{user_auth_type=PASSWORD|FINGERPRINT}");
  KmParam a2 = {0x100001f8u, 0xffffffffLL, nullptr, 0};
  Check("km.describe_auth_type_any", KmDescribeParams(&a2, 1) == "{user_auth_type=ANY}");
  KmParam a3 = {0x100001f8u, 0x14, nullptr, 0};
  Check("km.describe_auth_type_unknown_bits", KmDescribeParams(&a3, 1) == "{user_auth_type=0x14}");
  KmParam unk = {0x30123456u, 9, nullptr, 0};
  Check("km.describe_unknown_tag", KmDescribeParams(&unk, 1) == "{tag_0x30123456=9}");
  const uint8_t text[] = "hello";
  KmParam c = {0x900002c4u, 0, text, 5};  // attestation_challenge
  Check("km.describe_printable_bytes", KmDescribeParams(&c, 1) == "{attestation_challenge=\"hello\"}");
  const uint8_t bin[] = {0x01, 0xab};
  KmParam c2 = {0x900002c4u, 0, bin, 2};
  Check("km.describe_binary_bytes", KmDescribeParams(&c2, 1) == "{attestation_challenge=01ab}");
  KmParam e = {0x900002c4u, 0, nullptr, 0};
  Check("km.describe_empty_bytes", KmDescribeParams(&e, 1) == "{attestation_challenge=\"\"}");
  Check("km.describe_empty_list", KmDescribeParams(nullptr, 0) == "{}");
  Check("km.tag_name", std::string(KmTagName(0x900002c5u)) == "attestation_application_id");
  Check("km.tag_name_unknown", KmTagName(0x12345678u) == nullptr);
  Check("km.err_ok", std::string(teesim_km_err_name(0)) == "OK");
  Check("km.err_known", std::string(teesim_km_err_name(-38)) == "INVALID_ARGUMENT");
  Check("km.err_last", std::string(teesim_km_err_name(-1000)) == "UNKNOWN_ERROR");
  Check("km.err_unknown", std::string(teesim_km_err_name(12345)) == "?");
  Check("km.value_kind", teesim_km_tag_value_kind(0x100001f8u) == KM_VALUE_UINT32 &&
                             teesim_km_tag_value_kind(0x10000002u) == KM_VALUE_INT32 &&
                             teesim_km_tag_value_kind(0x900002c4u) == KM_VALUE_BYTES &&
                             teesim_km_tag_value_kind(0x600002bdu) == KM_VALUE_INT64 &&
                             teesim_km_tag_value_kind(0x500000c8u) == KM_VALUE_UINT64 &&
                             teesim_km_tag_value_kind(0x700001f7u) == KM_VALUE_BOOL);
}

static void RedactTests() {
  const uint8_t value[] = {'b', 'c'};
  RedactSetSalt(nullptr, 0);
  Check("redact.unsalted", RedactToken(value, 2) == "~?/2");
  const uint8_t salt[] = {'a'};
  RedactSetSalt(salt, 1);
  // SHA-256("abc") = ba7816bf 8f01cfea ...
  Check("redact.sha256_abc", RedactToken(value, 2) == "~ba7816bf/2");
  Check("redact.null_value", RedactToken(nullptr, 0).size() > 3);
  const uint8_t id[] = {'S', 'N', '1'};
  KmParam p = {0x900002c9u, 0, id, 3};  // attestation_id_serial is logged as a token
  const std::string tok = RedactToken(id, 3);
  Check("redact.serial_tokenized", KmDescribeParams(&p, 1) == "{attestation_id_serial=" + tok + "}");
}

int main() {
  JsonTests();
  Base64Tests();
  ControlTests();
  KmNameTests();
  RedactTests();
  printf("KAT-SUMMARY passed=%d failed=%d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
