// Host stand-in for bionic's <sys/system_properties.h>: no property is ever set.
#ifndef MAYHEM_SHIM_SYS_SYSTEM_PROPERTIES_H
#define MAYHEM_SHIM_SYS_SYSTEM_PROPERTIES_H

#define PROP_VALUE_MAX 92

#ifdef __cplusplus
extern "C" {
#endif
static inline int __system_property_get(const char *, char *value) {
  value[0] = '\0';
  return 0;
}
#ifdef __cplusplus
}
#endif

#endif
