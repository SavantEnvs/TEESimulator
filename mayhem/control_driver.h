// Runs common/control.cpp's HandleConnection over a socketpair. control.cpp keeps everything in an
// anonymous namespace, so the harness translation unit includes the source itself; the only thing
// replaced is the SO_PEERCRED root check, which a socketpair can only answer with the caller's own
// uid (the check is the access control for the real socket, not a parser, so it is not under test).
#ifndef MAYHEM_CONTROL_DRIVER_H
#define MAYHEM_CONTROL_DRIVER_H

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

static int mayhem_getsockopt(int fd, int level, int name, void *val, socklen_t *len) {
  if (level == SOL_SOCKET && name == SO_PEERCRED) {
    struct ucred c;
    c.pid = getpid();
    c.uid = 0;
    c.gid = 0;
    memcpy(val, &c, sizeof(c));
    *len = sizeof(c);
    return 0;
  }
  return getsockopt(fd, level, name, val, len);
}
#define getsockopt mayhem_getsockopt
#include "../common/control.cpp"
#undef getsockopt

// Feed `stream` (already framed) to HandleConnection and return the bytes it wrote back.
static std::string RunConnection(const std::string &stream) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) abort();
  int big = 4 << 20;
  setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
  size_t off = 0;
  while (off < stream.size()) {
    ssize_t w = write(sv[1], stream.data() + off, stream.size() - off);
    if (w <= 0) abort();
    off += static_cast<size_t>(w);
  }
  shutdown(sv[1], SHUT_WR);
  HandleConnection(sv[0]);  // closes sv[0]
  std::string out;
  char buf[4096];
  for (;;) {
    ssize_t r = read(sv[1], buf, sizeof(buf));
    if (r <= 0) break;
    out.append(buf, static_cast<size_t>(r));
  }
  close(sv[1]);
  return out;
}

static std::string Frame(const std::string &payload) {
  uint32_t n = static_cast<uint32_t>(payload.size());
  std::string f;
  f.push_back(char(n >> 24));
  f.push_back(char(n >> 16));
  f.push_back(char(n >> 8));
  f.push_back(char(n));
  return f + payload;
}

// Split a reply stream into its frames; false if the stream is not a whole number of frames.
static bool SplitFrames(const std::string &s, std::vector<std::string> &frames) {
  size_t i = 0;
  while (i < s.size()) {
    if (s.size() - i < 4) return false;
    uint32_t n = (uint32_t(uint8_t(s[i])) << 24) | (uint32_t(uint8_t(s[i + 1])) << 16) |
                 (uint32_t(uint8_t(s[i + 2])) << 8) | uint32_t(uint8_t(s[i + 3]));
    i += 4;
    if (n > s.size() - i) return false;
    frames.push_back(s.substr(i, n));
    i += n;
  }
  return true;
}

#endif
