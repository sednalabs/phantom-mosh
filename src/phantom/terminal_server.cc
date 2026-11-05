// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Experimental SSH-bootstrapped SSP terminal. See terminal-integration.md.
#include "session_offer.h"
#include "src/statesync/completeterminal.h"
#include "src/statesync/user.h"
#include "ssp_transport.h"
#include "terminal_pty.h"
#include <cerrno>
#include <charconv>
#include <clocale>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace phantom;
namespace {
volatile sig_atomic_t stopping = 0;
void stop_signal( int )
{
  stopping = 1;
}
class Fd
{
public:
  explicit Fd( int value ) : value_( value ) {}
  ~Fd()
  {
    if ( value_ >= 0 )
      ::close( value_ );
  }
  Fd( const Fd& ) = delete;
  Fd& operator=( const Fd& ) = delete;
  int get() const { return value_; }
  int release()
  {
    int old = value_;
    value_ = -1;
    return old;
  }

private:
  int value_;
};
std::uint64_t number( std::string_view value )
{
  std::uint64_t out = 0;
  auto parsed = std::from_chars( value.data(), value.data() + value.size(), out );
  if ( value.empty() || parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size() )
    throw Error( "invalid session lifetime option" );
  return out;
}
std::string ssh_local_host()
{
  const char* text = std::getenv( "SSH_CONNECTION" );
  if ( !text || std::char_traits<char>::length( text ) > 256 )
    throw Error( "SSH connection context required" );
  std::istringstream fields( text );
  std::string client, client_port, server, server_port, extra;
  if ( !( fields >> client >> client_port >> server >> server_port ) || fields >> extra )
    throw Error( "invalid SSH connection context" );
  const auto cp = number( client_port ), sp = number( server_port );
  if ( !cp || cp > 65535 || !sp || sp > 65535 )
    throw Error( "invalid SSH connection context" );
  UdpEndpoint::parse( client, static_cast<std::uint16_t>( cp ) );
  return UdpEndpoint::parse( server, static_cast<std::uint16_t>( sp ) ).host();
}
void write_frame( int fd, std::string_view frame )
{
  // Dedicated pipes, one bounded frame. The parent owns the global SSH timeout;
  // a broken channel is a failure, never a reason to log the frame.
  while ( !frame.empty() ) {
    const auto written = ::write( fd, frame.data(), frame.size() );
    if ( written < 0 && errno == EINTR )
      continue;
    if ( written <= 0 )
      throw Error( "session startup write failed" );
    frame.remove_prefix( static_cast<std::size_t>( written ) );
  }
}
// This dedicated daemon has no unrelated children. Subreaping lets ordinary
// shell job-control groups be adopted after the shell dies. pidfds prevent PID
// reuse from redirecting cleanup signals. This is not a hostile-process sandbox.
class Descendants
{
public:
  Descendants()
  {
    if ( ::prctl( PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0 ) != 0 )
      throw Error( "terminal child supervision unavailable" );
    const int self = static_cast<int>( ::syscall( SYS_pidfd_open, ::getpid(), 0U ) );
    if ( self < 0 )
      throw Error( "terminal pidfd supervision unavailable" );
    const auto result = ::syscall( SYS_pidfd_send_signal, self, 0, nullptr, 0U );
    ::close( self );
    if ( result != 0 )
      throw Error( "terminal pidfd signaling unavailable" );
  }
  ~Descendants() { (void)drain(); }
  bool drain() noexcept
  {
    try {
      const auto deadline = session_time_ms() + 5000;
      for ( ;; ) {
        // Reap exited adopted children, then find live direct children. Killing
        // parents can cause another generation to be adopted on the next pass.
        for ( ;; ) {
          const auto reaped = ::waitpid( -1, nullptr, WNOHANG );
          if ( reaped > 0 || ( reaped < 0 && errno == EINTR ) )
            continue;
          if ( reaped < 0 )
            return errno == ECHILD; // authoritative, not a procfs snapshot
          break;                    // live children still exist
        }
        DIR* directory = ::opendir( "/proc" );
        if ( !directory )
          return false;
        struct DirectoryCloser
        {
          void operator()( DIR* value ) const { ::closedir( value ); }
        };
        std::unique_ptr<DIR, DirectoryCloser> entries( directory );
        while ( const auto* entry = ::readdir( entries.get() ) ) {
          pid_t pid = 0;
          const std::string_view name( entry->d_name );
          const auto parsed = std::from_chars( name.data(), name.data() + name.size(), pid );
          if ( parsed.ec != std::errc {} || parsed.ptr != name.data() + name.size() || pid <= 0 )
            continue;
          std::ifstream candidate( "/proc/" + std::to_string( pid ) + "/status" );
          std::string label;
          bool child = false;
          while ( candidate >> label ) {
            if ( label == "PPid:" ) {
              pid_t parent;
              if ( candidate >> parent )
                child = parent == ::getpid();
              break;
            }
            std::string rest;
            std::getline( candidate, rest );
          }
          if ( !child )
            continue;
          const int handle = static_cast<int>( ::syscall( SYS_pidfd_open, pid, 0U ) );
          if ( handle < 0 )
            continue;
          // Check parentage AFTER pinning the identity. Never signal a process
          // solely because a numeric PID appeared in an earlier snapshot.
          std::ifstream status( "/proc/" + std::to_string( pid ) + "/status" );
          std::string field;
          bool ours = false;
          while ( status >> field ) {
            if ( field == "PPid:" ) {
              pid_t parent;
              if ( status >> parent )
                ours = parent == ::getpid();
              break;
            }
            std::string rest;
            std::getline( status, rest );
          }
          if ( ours )
            (void)::syscall( SYS_pidfd_send_signal, handle, SIGKILL, nullptr, 0U );
          ::close( handle );
        }
        if ( session_time_ms() >= deadline )
          return false;
        (void)::poll( nullptr, 0, 10 );
      }
    } catch ( ... ) {
      return false;
    }
  }
};
int daemon_main( int offer_fd, const std::string& host, RemotePolicy policy )
{
  try {
    Fd offer( offer_fd );
    // The shell is created in the authenticated SSH-launched daemon, before
    // any session secret exists. Unconfirmed channel expiry destroys this PTY.
    if ( !std::setlocale( LC_ALL, "C.UTF-8" ) || ::setenv( "TERM", "xterm-256color", 1 ) )
      throw Error( "terminal locale setup failed" );
    Descendants descendants;
    auto pty = std::make_unique<TerminalPty>( std::vector<std::string> { "/bin/sh", "-i" }, 24, 80 );
    auto socket = SessionSocket::bind( host );
    auto secret = Bootstrap::random();
    auto frame = make_session_offer( socket.local(), secret, TERMINAL_PROFILE );
    const auto started = session_time_ms();
    Terminal::Complete screen( 80, 24 );
    Network::UserStream initial_input;
    SspTransport<Terminal::Complete, Network::UserStream> network(
      screen,
      initial_input,
      SessionChannel::server( std::move( socket ), std::move( secret ), started, policy ),
      started );
    write_frame( offer.get(), frame.view() );
    frame.clear();
    ::close( offer.release() );
    std::string pending;
    bool eof = false;
    bool shell_exited = false;
    std::uint64_t close_deadline = 0;
    while ( network.state() != ChannelState::closed ) {
      const auto now = session_time_ms();
      if ( !shell_exited ) {
        int shell_status;
        shell_exited = pty->exited( shell_status );
        if ( shell_exited && !descendants.drain() )
          throw Error( "terminal descendants did not exit" );
      }
      network.service( now );
      if ( network.state() == ChannelState::closed )
        break;
      if ( !network.shutdown_in_progress() ) {
        auto& terminal = network.get_current_state();
        Network::UserStream input;
        input.apply_string( network.get_remote_diff() );
        if ( input.size() > 65536 )
          throw Error( "terminal input budget exceeded" );
        for ( unsigned i = 0; i < input.size(); ++i ) {
          const auto& action = input.get_action( i );
          if ( const auto* resize = dynamic_cast<const Parser::Resize*>( &action ) ) {
            if ( resize->width < 1 || resize->width > 512 || resize->height < 1 || resize->height > 256 )
              throw Error( "terminal dimensions outside budget" );
            pty->resize( static_cast<unsigned short>( resize->height ),
                         static_cast<unsigned short>( resize->width ) );
          }
          pending += terminal.act( action );
          if ( pending.size() > 65536 )
            throw Error( "terminal write budget exceeded" );
        }
        // SSP ACK-only frames advance remote state numbers without carrying
        // user input. Echo-acknowledging them creates an idle ACK feedback loop.
        if ( !input.empty() )
          terminal.register_input_frame( network.get_remote_state_num(), now );
        terminal.set_echo_ack( now );
        if ( !pending.empty() ) {
          const auto count = ::write( pty->fd(), pending.data(), pending.size() );
          if ( count > 0 )
            pending.erase( 0, static_cast<std::size_t>( count ) );
          else if ( count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK && errno != EIO )
            throw Error( "terminal input failed" );
        }
        if ( !eof ) {
          char buffer[4096];
          const auto count = ::read( pty->fd(), buffer, sizeof buffer );
          if ( count > 0 ) {
            pending += terminal.act( std::string( buffer, static_cast<std::size_t>( count ) ) );
            if ( pending.size() > 65536 )
              throw Error( "terminal response budget exceeded" );
          } else if ( count == 0 || ( count < 0 && errno == EIO ) ) {
            eof = true;
          } else if ( errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK ) {
            throw Error( "terminal output failed" );
          }
        }
        if ( eof || stopping )
          network.start_shutdown();
      }
      if ( network.shutdown_ack_timed_out() && !network.shutdown_acknowledged() )
        throw Error( "terminal shutdown acknowledgement timed out" );
      if ( !close_deadline && ( network.shutdown_acknowledged() || network.counterparty_shutdown_ack_sent() ) )
        close_deadline = now + 5000;
      // SessionChannel deliberately gives CLOSE initiation to the client.
      // Keep serving its close handshake after final SSP state acknowledgement.
      if ( close_deadline && now >= close_deadline && network.state() != ChannelState::closing )
        throw Error( "terminal channel close timed out" );
      const auto fds = network.fds();
      pollfd events[2] = { { fds.at( 0 ), POLLIN, 0 },
                           { eof || network.shutdown_in_progress() ? -1 : pty->fd(),
                             static_cast<short>( POLLIN | ( pending.empty() ? 0 : POLLOUT ) ),
                             0 } };
      const int ready = ::poll( events, 2, std::min( 100, network.wait_time() ) );
      if ( ready < 0 && errno != EINTR )
        throw Error( "terminal event wait failed" );
    }
    const bool acknowledged = network.end_reason() == ChannelEnd::peer_closed;
    network.stop();
    pty.reset();
    const bool cleaned = descendants.drain();
    return !acknowledged ? 2 : ( cleaned ? 0 : 3 );
  } catch ( ... ) {
    return 1;
  } // Never write secret-bearing diagnostics from the daemon.
}
void detach_child( int pipe_fd, const std::string& host, RemotePolicy policy )
{
  if ( ::setsid() < 0 )
    ::_exit( 1 );
  const auto second = ::fork();
  if ( second < 0 )
    ::_exit( 1 );
  if ( second > 0 )
    ::_exit( 0 );
  // Preserve only one offer pipe at fd 3, then stdio to /dev/null. close_range
  // is required; a platform lacking it fails before generating any secret.
  if ( pipe_fd != 3 && ::dup2( pipe_fd, 3 ) < 0 )
    ::_exit( 1 );
  if ( ::syscall( SYS_close_range, 4U, ~0U, 0U ) < 0 )
    ::_exit( 1 );
  int null = ::open( "/dev/null", O_RDWR | O_CLOEXEC );
  if ( null < 0 )
    ::_exit( 1 );
  for ( int target = 0; target < 3; ++target )
    if ( ::dup2( null, target ) < 0 )
      ::_exit( 1 );
  if ( null > 3 )
    ::close( null );
  struct sigaction action
  {};
  action.sa_handler = stop_signal;
  ::sigemptyset( &action.sa_mask );
  for ( int sig : { SIGTERM, SIGINT, SIGHUP } )
    if ( ::sigaction( sig, &action, nullptr ) != 0 )
      ::_exit( 1 );
  // Returning from daemon_main destroys secret-bearing owners before _exit.
  const int status = daemon_main( 3, host, policy );
  ::_exit( status );
}
void launch( const std::string& host, RemotePolicy policy )
{
  struct stat channel
  {};
  if ( ::fstat( STDOUT_FILENO, &channel ) < 0 || ( !S_ISFIFO( channel.st_mode ) && !S_ISSOCK( channel.st_mode ) ) )
    throw Error( "session startup requires a dedicated output pipe" );
  ::signal( SIGPIPE, SIG_IGN );
  int ends[2];
  if ( ::pipe2( ends, O_CLOEXEC ) != 0 )
    throw Error( "session startup pipe failed" );
  Fd read_end( ends[0] ), write_end( ends[1] );
  const auto child = ::fork();
  if ( child < 0 )
    throw Error( "session process creation failed" );
  if ( child == 0 ) {
    ::close( read_end.release() );
    detach_child( write_end.release(), host, policy );
    ::_exit( 1 );
  }
  ::close( write_end.release() );
  int status = 0;
  while ( ::waitpid( child, &status, 0 ) < 0 )
    if ( errno != EINTR )
      throw Error( "session child wait failed" );
  if ( !WIFEXITED( status ) || WEXITSTATUS( status ) != 0 )
    throw Error( "session startup failed" );
  TerminalOfferDecoder decoder;
  struct Buffer
  {
    std::array<char, SESSION_OFFER_MAX + 1> data {};
    ~Buffer() { OPENSSL_cleanse( data.data(), data.size() ); }
  } buffer;
  const auto started = session_time_ms();
  for ( ;; ) {
    const auto spent = session_time_ms() - started;
    if ( spent >= 10000 )
      throw Error( "session startup timed out" );
    pollfd event { read_end.get(), POLLIN, 0 };
    const int ready = ::poll( &event, 1, static_cast<int>( 10000 - spent ) );
    if ( ready < 0 && errno == EINTR )
      continue;
    if ( ready <= 0 || event.revents & ( POLLERR | POLLNVAL ) )
      throw Error( "session startup pipe failed" );
    const auto count = ::read( read_end.get(), buffer.data.data(), buffer.data.size() );
    if ( count < 0 && errno == EINTR )
      continue;
    if ( count < 0 )
      throw Error( "session startup pipe failed" );
    if ( !count )
      break;
    decoder.feed( { buffer.data.data(), static_cast<std::size_t>( count ) } );
    OPENSSL_cleanse( buffer.data.data(), buffer.data.size() );
  }
  auto offer = decoder.finish();
  auto frame = make_session_offer( offer.server, offer.secret, TERMINAL_PROFILE );
  write_frame( STDOUT_FILENO, frame.view() );
  // Destructors clear both parent-side representations before exit/SSH EOF.
}
}
int main( int argc, char** argv )
{
  try {
    if ( argc < 3 || std::string_view( argv[1] ) != "--terminal-profile"
         || std::string_view( argv[2] ) != TERMINAL_PROFILE )
      throw Error( "usage: phantom-mosh-terminal-server --terminal-profile phantom-mosh/terminal/draft-01" );
    RemotePolicy policy;
    // Established terminals retain state during long disconnections.
    policy.idle_ms = 0;
    for ( int i = 3; i < argc; i += 2 ) {
      if ( i + 1 == argc )
        throw Error( "missing session lifetime option" );
      const std::string_view option( argv[i] );
      const auto value = number( argv[i + 1] );
      if ( option == "--startup-ms" )
        policy.startup_ms = value;
      else if ( option == "--path-ms" )
        policy.path_ms = value;
      else if ( option == "--drain-ms" )
        policy.drain_ms = value;
      else if ( option == "--idle-ms" )
        policy.idle_ms = value;
      else
        throw Error( "unknown session lifetime option" );
    }
    // Validate before forking, as well as in the owner. No synthetic keys.
    if ( !policy.startup_ms || policy.startup_ms > 120000 || !policy.path_ms || policy.path_ms > 120000
         || !policy.drain_ms || policy.drain_ms > 10000 )
      throw Error( "invalid session lifetime policy" );
    launch( ssh_local_host(), policy );
    return 0;
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
