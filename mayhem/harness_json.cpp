// libFuzzer harness for common/json.cpp, the tjson reader the control channel parses every daemon
// message with. Entry: arbitrary bytes as a JSON document; on success the whole tree is walked.
#include <stddef.h>
#include <stdint.h>

#include <string>

#include "json.hpp"

namespace {
size_t Walk(const tjson::Value &v) {
  size_t n = 1;
  switch (v.type()) {
    case tjson::Value::Array:
      for (size_t i = 0; i < v.size(); ++i) n += Walk(v.at(i));
      break;
    case tjson::Value::Object:
      break;
    case tjson::Value::String:
      n += v.as_string().size();
      break;
    case tjson::Value::Number:
      n += static_cast<size_t>(v.as_int(0) != 0) + static_cast<size_t>(v.as_double(0.0) != 0.0);
      break;
    case tjson::Value::Bool:
      n += v.as_bool(false);
      break;
    case tjson::Value::Null:
      break;
  }
  return n;
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > (1u << 20)) return -1;
  tjson::Value root;
  if (!tjson::parse(reinterpret_cast<const char *>(data), size, root)) return 0;
  Walk(root);
  tjson::Value copy = root;  // deep copy of whatever tree was built
  Walk(copy);
  // The control-channel keys, looked up on every parsed object.
  static const char *const kKeys[] = {"type", "epoch", "profiles", "bootInfo", "redactSalt", "id"};
  for (const char *k : kKeys) {
    if (const tjson::Value *c = copy.get(k)) Walk(*c);
  }
  return 0;
}
