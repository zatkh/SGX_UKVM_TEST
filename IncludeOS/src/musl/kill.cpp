#include "common.hpp"
#include <kernel/syscalls.hpp>

int sys_kill(pid_t /*pid*/, int /*sig*/) {
  panic("KILL called");
}

int sys_tkill(int /*tid*/, int /*sig*/) {
#ifndef INCLUDEOS_SINGLE_THREADED
#   warning "tkill not implemented for threaded IncludeOS"
#endif
  panic("TKILL called");
}

int sys_tgkill(int /*tgid*/, int /*tid*/, int /*sig*/) {
  panic("TGKILL called");
}

extern "C"
long syscall_SYS_kill(pid_t pid, int sig) {
  return strace(sys_kill, "kill", pid, sig);
}

extern "C"
long syscall_SYS_tkill(int tid, int sig) {
  return strace(sys_tkill, "tkill", tid, sig);
}

extern "C"
long syscall_SYS_tgkill(int tgid, int tid, int sig)
{
  return strace(sys_tgkill, "tgkill", tgid, tid, sig);
}
