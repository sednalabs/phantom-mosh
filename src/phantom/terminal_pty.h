// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_TERMINAL_PTY_H
#define PHANTOM_MOSH_TERMINAL_PTY_H
#include <signal.h>
#include <string>
#include <sys/types.h>
#include <vector>

namespace phantom {
// Linux PTY ownership primitive. Construct BEFORE generating session secrets:
// fork duplicates the caller's address space even though exec closes descriptors.
// Caller must retain SIGCHLD=SIG_DFL without SA_NOCLDWAIT and exclusive reaping
// of this child throughout the object's lifetime. No concurrent fork/signal changes.
// Cleanup kills the initial process group, not separate shell job-control groups;
// this is not whole-session containment and must not be used as that guarantee.
// The command uses an absolute executable path and argv, never shell fallback.
class TerminalPty
{
public:
  TerminalPty( const std::vector<std::string>& argv,
               unsigned short rows,
               unsigned short columns,
               int startup_timeout_ms = 5000,
               const volatile sig_atomic_t* cancellation = nullptr );
  ~TerminalPty();
  TerminalPty( const TerminalPty& ) = delete;
  TerminalPty& operator=( const TerminalPty& ) = delete;
  // Borrowed, nonblocking master. Caller handles partial writes/EAGAIN and Linux
  // EIO at slave close. Never close or transfer this descriptor.
  int fd() const noexcept { return master_; }
  pid_t pid() const noexcept { return child_; }
  void resize( unsigned short rows, unsigned short columns );
  // Nonblocking reap. Returns true when the child has exited, preserving status.
  bool exited( int& status );
  // Signal the owned group/leader and reap for at most one second. On false,
  // ownership passes to the caller/subreaper; no later destructor retry occurs.
  // A kernel-uninterruptible child may survive this deadline, so false must
  // never be reported as successful cleanup. This is not process containment.
  bool terminate() noexcept;

private:
  int master_ = -1;
  pid_t child_ = -1;
  int status_ = 0;
  bool cleanup_failed_ = false;
};
} // namespace phantom
#endif
