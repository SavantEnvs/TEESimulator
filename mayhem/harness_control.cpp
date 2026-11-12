// libFuzzer harness for the daemon <-> lib control channel (common/control.cpp). The input is the
// stream a daemon connection delivers to HandleConnection over a socketpair. First byte selects the
// framing: 0 = the remaining bytes verbatim (length-prefix handling is fuzzed too), anything else =
// the remaining bytes split at 0x00 into JSON payloads, each given a correct frame header so the
// message handlers (config, resign, getUsage, ping) are reached without guessing lengths.
#include <stdio.h>
#include <string.h>

#include "control_driver.h"
#include "router_stub.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // A `config` message can set the process-global redaction salt; start every input unsalted.
  RedactSetSalt(nullptr, 0);
  if (size < 2 || size > 16384) return -1;
  std::string stream;
  const char *body = reinterpret_cast<const char *>(data) + 1;
  size_t n = size - 1;
  if (data[0] == 0) {
    stream.assign(body, n);
  } else {
    size_t start = 0;
    for (size_t i = 0; i <= n; ++i) {
      if (i == n || body[i] == 0) {
        if (i > start) stream += Frame(std::string(body + start, i - start));
        start = i + 1;
      }
    }
  }
  std::string reply = RunConnection(stream);

  // Whatever the input, every frame the lib wrote back is a whole, parseable JSON message.
  std::vector<std::string> frames;
  if (!SplitFrames(reply, frames)) abort();
  for (const std::string &f : frames) {
    tjson::Value v;
    if (!tjson::parse(f.data(), f.size(), v) || !v.get("type")) abort();
  }
  return 0;
}
