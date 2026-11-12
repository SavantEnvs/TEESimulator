// A recording stand-in for the KeyMint/keystore1 routers that common/control.cpp stages config into.
// The real ones build a Rust TA per profile; here a profile is "applied" unless its id is "bad", and
// the staged shape is kept so a known-answer test can read back what the control channel decoded.
#include <string>
#include <vector>

#include "router_stub.h"

namespace mstub {
State g_state;
}

extern "C" {
void teesim_cfg_begin(const TsBootInfo *boot) {
  mstub::g_state = mstub::State{};
  mstub::g_state.began = true;
  mstub::g_state.locked = boot->device_locked;
  mstub::g_state.boot_state = boot->verified_boot_state;
  mstub::g_state.attest_tee = boot->attest_version_tee;
  mstub::g_state.attest_sb = boot->attest_version_strongbox;
  mstub::g_state.vb_key_len = boot->verified_boot_key_len;
  mstub::g_state.vb_hash_len = boot->verified_boot_hash_len;
  mstub::g_state.module_hash_len = boot->module_hash_len;
}

bool teesim_cfg_add_profile(const TsProfile *p) {
  mstub::Profile rec;
  rec.id = p->id;
  rec.mode = p->mode ? p->mode : "";
  rec.keybox_len = p->keybox_len;
  rec.security_level = p->security_level;
  rec.os_version = p->os_version;
  rec.has_ids = p->ids != nullptr;
  if (p->ids) rec.brand.assign(reinterpret_cast<const char *>(p->ids->brand), p->ids->brand_len);
  for (int i = 0; i < p->n_packages; ++i) {
    rec.packages.push_back(p->packages[i]);
    rec.package_users.push_back(p->package_users[i]);
  }
  for (int i = 0; i < p->n_uids; ++i) {
    rec.uids.push_back(p->uids[i]);
    rec.uid_packages.push_back(p->uid_packages[i]);
  }
  mstub::g_state.profiles.push_back(rec);
  return rec.id != "bad";
}

int teesim_cfg_commit(uint64_t epoch, char *err, size_t err_len) {
  mstub::g_state.committed = true;
  mstub::g_state.epoch = epoch;
  int n = 0;
  for (const auto &p : mstub::g_state.profiles) n += p.id != "bad";
  if (err_len > 0) err[0] = '\0';
  return n;
}

bool teesim_cfg_resign(const char *profile_id, const uint8_t *, size_t leaf_len, TsCertSink sink,
                       void *ctx) {
  if (std::string(profile_id) != "p1" || leaf_len < 3) return false;
  static const uint8_t kDer[3] = {0x30, 0x01, 0x00};
  sink(ctx, kDer, sizeof(kDer));
  return true;
}

const char *teesim_hook_name(void) { return "mayhem-stub"; }

void teesim_cfg_set_rkp_deleted(const char *const *names, size_t n) {
  for (size_t i = 0; i < n; ++i) mstub::g_state.rkp_deleted.push_back(names[i]);
}

char *teesim_usage_json_alloc(void) { return strdup("[{\"uid\":1000,\"count\":2}]"); }
char *teesim_rkp_reassert_json_alloc(void) { return strdup("[]"); }
}
