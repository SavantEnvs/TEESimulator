#ifndef MAYHEM_ROUTER_STUB_H
#define MAYHEM_ROUTER_STUB_H

#include <string.h>

#include <string>
#include <vector>

#include "control.h"

namespace mstub {
struct Profile {
  std::string id, mode, brand;
  size_t keybox_len = 0;
  int security_level = 0;
  uint32_t os_version = 0;
  bool has_ids = false;
  std::vector<std::string> packages, uid_packages;
  std::vector<int32_t> package_users, uids;
};
struct State {
  bool began = false, committed = false, locked = false;
  uint64_t epoch = 0;
  int boot_state = 0, attest_tee = 0, attest_sb = 0;
  size_t vb_key_len = 0, vb_hash_len = 0, module_hash_len = 0;
  std::vector<Profile> profiles;
  std::vector<std::string> rkp_deleted;
};
extern State g_state;
}  // namespace mstub

#endif
