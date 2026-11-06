// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "terminal_pty.h"
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

namespace phantom {
namespace {
void dimensions( unsigned short rows, unsigned short columns )
{
  if ( rows == 0 || columns == 0 )
    throw std::invalid_argument( "PTY dimensions must be nonzero" );
}
}
TerminalPty::TerminalPty( const std::vector<std::string>& argv,
                          unsigned short rows,
                          unsigned short columns,
                          int startup_timeout_ms,
                          const volatile sig_atomic_t* cancellation )
{
  dimensions( rows, columns );
  if ( startup_timeout_ms < 1 || startup_timeout_ms > 120000 )
    throw std::invalid_argument( "invalid PTY startup timeout" );
  if ( cancellation && *cancellation )
    throw std::runtime_error( "PTY startup cancelled" );
  struct sigaction reaping
  {};
  if ( ::sigaction( SIGCHLD, nullptr, &reaping ) != 0 || reaping.sa_handler != SIG_DFL
       || ( reaping.sa_flags & SA_NOCLDWAIT ) )
    throw std::invalid_argument( "PTY requires exclusive child reaping" );
  if ( argv.empty() || argv.front().empty() || argv.front().front() != '/' )
    throw std::invalid_argument( "absolute PTY command required" );
  std::vector<char*> args;
  for ( const auto& arg : argv ) {
    if ( arg.find( '\0' ) != std::string::npos )
      throw std::invalid_argument( "NUL in PTY argument" );
    args.push_back( const_cast<char*>( arg.c_str() ) );
  }
  args.push_back( nullptr );
  master_ = ::posix_openpt( O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK );
  int slave = -1;
  int errors[2] = { -1, -1 };
  try {
    char path[PATH_MAX];
    if ( master_ < 0 || ::grantpt( master_ ) || ::unlockpt( master_ ) || ::ptsname_r( master_, path, sizeof path ) )
      throw std::runtime_error( "PTY allocation failed" );
    slave = ::open( path, O_RDWR | O_NOCTTY | O_CLOEXEC );
    if ( slave < 0 || ::pipe2( errors, O_CLOEXEC ) )
      throw std::runtime_error( "PTY child setup failed" );
    const int error_writer = ::fcntl( errors[1], F_DUPFD_CLOEXEC, 10 );
    if ( error_writer < 0 )
      throw std::runtime_error( "PTY error descriptor failed" );
    ::close( errors[1] );
    errors[1] = error_writer;
    resize( rows, columns );
    child_ = ::fork();
    if ( child_ < 0 )
      throw std::runtime_error( "PTY fork failed" );
    if ( child_ == 0 ) {
      // Only async-signal-safe operations after fork. Error pipe occupies fd 3;
      // close_range prevents accidental inheritance of network/startup handles.
      ::close( errors[0] );
      bool ok = ::setsid() >= 0 && ::ioctl( slave, TIOCSCTTY, 0 ) == 0;
      for ( int fd = 0; fd < 3 && ok; ++fd )
        ok = ::dup2( slave, fd ) >= 0 && ::fcntl( fd, F_SETFD, 0 ) == 0;
      const bool remapped = ::dup3( errors[1], 3, O_CLOEXEC ) >= 0;
      ok = ok && remapped;
      if ( ok )
        ok = ::syscall( SYS_close_range, 4U, ~0U, 0U ) == 0;
      sigset_t empty;
      ::sigemptyset( &empty );
      ok = ok && ::sigprocmask( SIG_SETMASK, &empty, nullptr ) == 0;
      struct sigaction action
      {};
      action.sa_handler = SIG_DFL;
      ::sigemptyset( &action.sa_mask );
      for ( int sig = 1; sig < NSIG; ++sig ) {
        if ( sig != SIGKILL && sig != SIGSTOP )
          ::sigaction( sig, &action, nullptr );
      }
      if ( ok )
        ::execv( args[0], args.data() );
      const char error = 'E';
      // If fd remapping failed, the original error descriptor is still live.
      const int error_fd = remapped ? 3 : errors[1];
      const auto ignored = ::write( error_fd, &error, 1 );
      (void)ignored;
      ::_exit( 127 );
    }
    ::close( slave );
    slave = -1;
    ::close( errors[1] );
    errors[1] = -1;
    char error;
    ssize_t count;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds( startup_timeout_ms );
    for ( ;; ) {
      if ( cancellation && *cancellation )
        throw std::runtime_error( "PTY startup cancelled" );
      if ( std::chrono::steady_clock::now() >= deadline )
        throw std::runtime_error( "PTY startup timed out" );
      pollfd event { errors[0], POLLIN, 0 };
      const int ready = ::poll( &event, 1, 20 );
      if ( ready < 0 && errno == EINTR )
        continue;
      if ( ready < 0 || event.revents & ( POLLERR | POLLNVAL ) )
        throw std::runtime_error( "PTY startup pipe failed" );
      if ( !ready )
        continue;
      count = ::read( errors[0], &error, 1 );
      if ( count < 0 && errno == EINTR )
        continue;
      break;
    }
    ::close( errors[0] );
    errors[0] = -1;
    if ( count != 0 )
      throw std::runtime_error( "PTY exec failed" );
  } catch ( ... ) {
    (void)terminate();
    if ( master_ >= 0 )
      ::close( master_ );
    if ( slave >= 0 )
      ::close( slave );
    for ( int fd : errors )
      if ( fd >= 0 )
        ::close( fd );
    throw;
  }
}
TerminalPty::~TerminalPty()
{
  (void)terminate();
  if ( master_ >= 0 )
    ::close( master_ );
}
bool TerminalPty::terminate() noexcept
{
  if ( child_ <= 0 )
    return !cleanup_failed_;
  // The unreaped child pins its identity until cleanup. Exclusive reaping is
  // required; never signal a PID after another owner has already reaped it.
  siginfo_t info {};
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds( 1 );
  int waited;
  do {
    waited = ::waitid( P_PID, static_cast<id_t>( child_ ), &info, WEXITED | WNOHANG | WNOWAIT );
  } while ( waited < 0 && errno == EINTR && std::chrono::steady_clock::now() < deadline );
  if ( waited < 0 ) {
    child_ = -1;
    cleanup_failed_ = true;
    return false;
  }
  ::kill( -child_, SIGKILL );
  ::kill( child_, SIGKILL );
  for ( ;; ) {
    const auto result = ::waitpid( child_, &status_, WNOHANG );
    if ( result == child_ ) {
      child_ = -1;
      return true;
    }
    if ( ( result < 0 && errno != EINTR ) || std::chrono::steady_clock::now() >= deadline ) {
      child_ = -1;
      cleanup_failed_ = true;
      return false;
    }
    (void)::poll( nullptr, 0, 10 );
  }
}
void TerminalPty::resize( unsigned short rows, unsigned short columns )
{
  dimensions( rows, columns );
  struct winsize size
  {};
  size.ws_row = rows;
  size.ws_col = columns;
  if ( ::ioctl( master_, TIOCSWINSZ, &size ) )
    throw std::runtime_error( "PTY resize failed" );
}
bool TerminalPty::exited( int& status )
{
  if ( cleanup_failed_ )
    throw std::runtime_error( "PTY cleanup did not complete" );
  if ( child_ > 0 ) {
    siginfo_t info {};
    int result;
    do {
      result = ::waitid( P_PID, static_cast<id_t>( child_ ), &info, WEXITED | WNOHANG | WNOWAIT );
    } while ( result < 0 && errno == EINTR );
    if ( result < 0 )
      throw std::runtime_error( "PTY wait failed" );
    if ( info.si_pid == 0 )
      return false;
    // Keep the leader unreaped until the owned group has been signalled.
    ::kill( -child_, SIGKILL );
    do {
      result = ::waitpid( child_, &status_, 0 );
    } while ( result < 0 && errno == EINTR );
    if ( result < 0 )
      throw std::runtime_error( "PTY reap failed" );
    child_ = -1;
  }
  status = status_;
  return true;
}
} // namespace phantom
