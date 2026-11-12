// Host stand-in for Android's liblog: the harnesses link the common/ sources on a plain Linux box,
// where the log sink is not the thing under test, so it discards.
#ifndef MAYHEM_SHIM_ANDROID_LOG_H
#define MAYHEM_SHIM_ANDROID_LOG_H

enum {
  ANDROID_LOG_UNKNOWN = 0,
  ANDROID_LOG_DEFAULT,
  ANDROID_LOG_VERBOSE,
  ANDROID_LOG_DEBUG,
  ANDROID_LOG_INFO,
  ANDROID_LOG_WARN,
  ANDROID_LOG_ERROR,
  ANDROID_LOG_FATAL,
  ANDROID_LOG_SILENT,
};

#ifdef __cplusplus
extern "C" {
#endif
static inline int __android_log_write(int, const char *, const char *) { return 1; }
static inline int __android_log_print(int, const char *, const char *, ...)
    __attribute__((format(printf, 3, 4)));
static inline int __android_log_print(int, const char *, const char *, ...) { return 1; }
#ifdef __cplusplus
}
#endif

#endif
