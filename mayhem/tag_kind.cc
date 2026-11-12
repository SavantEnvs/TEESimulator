// teesim_km_tag_value_kind lives in the Rust crate (rust/teesim-km/src/capi.rs), which needs the
// uninitialised third_party/keymint submodule to build. This is the same pure function of the tag.
#include "teesim_km.h"

extern "C" KmValueKind teesim_km_tag_value_kind(uint32_t tag) {
  constexpr uint32_t kUserAuthType = 0x10000000u | 504u;
  if (tag == kUserAuthType) return KM_VALUE_UINT32;
  switch (tag & 0xF0000000u) {
    case 0x70000000u: return KM_VALUE_BOOL;
    case 0x90000000u:
    case 0x80000000u: return KM_VALUE_BYTES;
    case 0x10000000u:
    case 0x20000000u: return KM_VALUE_INT32;
    case 0x30000000u:
    case 0x40000000u: return KM_VALUE_UINT32;
    case 0x50000000u:
    case 0xA0000000u: return KM_VALUE_UINT64;
    case 0x60000000u: return KM_VALUE_INT64;
    default: return KM_VALUE_INVALID;
  }
}
