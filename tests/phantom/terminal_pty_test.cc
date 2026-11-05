// SPDX-License-Identifier: GPL-3.0-or-later
#include "terminal_pty.h"
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
using phantom::TerminalPty;
void require( bool value, const char* message )
{
  if ( !value )
    throw std::runtime_error( message );
}
std::string output( TerminalPty& pty )
{
  std::string result;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds( 3 );
  for ( ;; ) {
    char bytes[4096];
    auto count = ::read( pty.fd(), bytes, sizeof bytes );
    if ( count > 0 )
      result.append( bytes, static_cast<std::size_t>( count ) );
    else if ( count == 0 || ( count < 0 && errno == EIO ) )
      return result;
    else if ( errno != EAGAIN && errno != EINTR )
      throw std::runtime_error( "PTY read failed" );
    require( std::chrono::steady_clock::now() < deadline, "PTY output timeout" );
    pollfd event { pty.fd(), POLLIN, 0 };
    ::poll( &event, 1, 10 );
  }
}
int main()
{
  try {
    TerminalPty pty(
      { "/bin/sh", "-c", "stty size; test -t 0 && test -t 1; printf 'utf8: λ\\n'; exit 7" }, 24, 80 );
    require( ( ::fcntl( pty.fd(), F_GETFL ) & O_NONBLOCK ) != 0, "master must be nonblocking" );
    require( ( ::fcntl( pty.fd(), F_GETFD ) & FD_CLOEXEC ) != 0, "master must be CLOEXEC" );
    const auto text = output( pty );
    require( text.find( "24 80" ) != std::string::npos && text.find( "utf8: λ" ) != std::string::npos,
             "PTY output and dimensions" );
    int status;
    for ( int i = 0; !pty.exited( status ); ++i ) {
      require( i < 100, "child exit timeout" );
      ::usleep( 1000 );
    }
    require( WIFEXITED( status ) && WEXITSTATUS( status ) == 7, "exit status preserved" );
    require( pty.exited( status ) && WEXITSTATUS( status ) == 7, "repeat reap" );
    TerminalPty resize( { "/bin/sh", "-c", "read x; stty size; printf '%s' \"$x\"" }, 24, 80 );
    resize.resize( 40, 120 );
    require( ::write( resize.fd(), "hello\n", 6 ) == 6, "PTY input" );
    const auto changed = output( resize );
    require( changed.find( "40 120" ) != std::string::npos && changed.find( "hello" ) != std::string::npos,
             "resize and input" );
    int leaked = ::open( "/dev/null", O_RDONLY );
    require( leaked >= 0, "test descriptor" );
    const std::string command = "test ! -e /proc/self/fd/" + std::to_string( leaked ) + "; echo isolated:$?";
    TerminalPty isolation( { "/bin/sh", "-c", command }, 24, 80 );
    ::close( leaked );
    require( output( isolation ).find( "isolated:0" ) != std::string::npos, "descriptor isolation" );
    bool failed = false;
    try {
      TerminalPty missing( { "/phantom-test-no-such-executable" }, 24, 80 );
    } catch ( const std::runtime_error& ) {
      failed = true;
    }
    require( failed, "exec rejection" );
    char script[] = "/tmp/phantom-pty-no-shebang-XXXXXX";
    int script_fd = ::mkstemp( script );
    require( script_fd >= 0, "temporary command" );
    require( ::write( script_fd, "exit 0\n", 7 ) == 7, "temporary command contents" );
    require( ::fchmod( script_fd, 0700 ) == 0, "temporary command mode" );
    ::close( script_fd );
    failed = false;
    try {
      TerminalPty no_shell( { script }, 24, 80 );
    } catch ( const std::runtime_error& ) {
      failed = true;
    }
    ::unlink( script );
    require( failed, "ENOEXEC must not invoke a shell" );
    for ( int mask = 1; mask < 8; ++mask ) {
      const pid_t child = ::fork();
      require( child >= 0, "closed stdio test fork" );
      if ( child == 0 ) {
        for ( int fd = 0; fd < 3; ++fd )
          if ( mask & ( 1 << fd ) )
            ::close( fd );
        try {
          int exit_code;
          {
            TerminalPty closed( { "/bin/sh", "-c", "test -t 0 && test -t 1 && test -t 2 && printf ok" }, 24, 80 );
            exit_code = output( closed ).find( "ok" ) == std::string::npos ? 1 : 0;
          }
          ::_exit( exit_code );
        } catch ( ... ) {
          ::_exit( 1 );
        }
      }
      require( ::waitpid( child, &status, 0 ) == child && WIFEXITED( status ) && WEXITSTATUS( status ) == 0,
               "all closed stdio permutations preserve terminal descriptors" );
    }
    struct sigaction original
    {
    }, altered {};
    require( ::sigaction( SIGCHLD, nullptr, &original ) == 0, "SIGCHLD query" );
    for ( int mode = 0; mode < 2; ++mode ) {
      altered = original;
      if ( mode == 0 )
        altered.sa_handler = SIG_IGN;
      else
        altered.sa_flags |= SA_NOCLDWAIT;
      require( ::sigaction( SIGCHLD, &altered, nullptr ) == 0, "SIGCHLD setup" );
      failed = false;
      try {
        TerminalPty invalid_reaping( { "/bin/true" }, 24, 80 );
      } catch ( const std::invalid_argument& ) {
        failed = true;
      }
      require( ::sigaction( SIGCHLD, &original, nullptr ) == 0, "SIGCHLD restore" );
      require( failed, "reject automatic child reaping" );
    }
    pid_t owned;
    {
      TerminalPty cleanup( { "/bin/sh", "-c", "sleep 60" }, 24, 80 );
      owned = cleanup.pid();
    }
    require( ::waitpid( owned, nullptr, WNOHANG ) == -1 && errno == ECHILD, "destructor reaps child" );
    std::cout << "terminal PTY tests passed\n";
    return 0;
  } catch ( const std::exception& error ) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
