// libFuzzer harness for common/km_names.cpp, the KeyMint tag/enum/error naming used by every log
// line. Entry: a list of records [u32 tag][i64 value][u8 blob_len][blob bytes] rendered with
// KmDescribeParams; an empty blob (len 0) is passed as a null pointer, as the marshallers do.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>
#include <vector>

#include "km_names.h"
#include "redact.h"

extern "C" const char *teesim_km_err_name(int32_t code);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 14 || size > 8192) return -1;
  int32_t code;
  memcpy(&code, data, 4);
  (void)teesim_km_err_name(code);
  uint32_t tag0;
  memcpy(&tag0, data + 4, 4);
  (void)KmTagName(tag0);

  std::vector<KmParam> params;
  size_t i = 8;
  while (size - i >= 13) {
    KmParam p{};
    memcpy(&p.tag, data + i, 4);
    memcpy(&p.int_value, data + i + 4, 8);
    size_t blen = data[i + 12];
    i += 13;
    if (blen > size - i) blen = size - i;
    p.blob = blen ? data + i : nullptr;
    p.blob_len = blen;
    i += blen;
    params.push_back(p);
  }
  const uint8_t salt[2] = {data[0], data[1]};
  RedactSetSalt(salt, sizeof(salt));
  std::string s = KmDescribeParams(params.data(), params.size());
  if (s.empty() || s.front() != '{' || s.back() != '}') abort();
  return 0;
}
