// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Experimental remote-session owner. No shell or PTY is created here.
#include "session_channel.h"
#include "session_offer.h"
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <sstream>
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
int daemon_main( int offer_fd, const std::string& host, RemotePolicy policy )
{
  try {
    Fd offer( offer_fd );
    auto socket = SessionSocket::bind( host );
    // All forks are finished BEFORE entropy, keys or packet counters exist.
    auto secret = Bootstrap::random();
    auto frame = make_session_offer( socket.local(), secret );
    auto owner = SessionChannel::server( std::move( socket ), std::move( secret ), session_time_ms(), policy );
    write_frame( offer.get(), frame.view() );
    frame.clear();
    ::close( offer.release() );
    while ( !stopping ) {
      // The shared pump owns control retries, key retirement and bounded I/O.
      // No shell is started and application DATA is deliberately discarded;
      // ChannelBatch erases its plaintext on destruction.
      owner->service( session_time_ms() );
      if ( owner->state() == ChannelState::closed || stopping )
        break;
      pollfd event { owner->fd(), POLLIN, 0 };
      const int ready = ::poll( &event, 1, owner->wait_ms( session_time_ms() ) );
      if ( ( ready < 0 && errno != EINTR ) || ( event.revents & POLLNVAL ) )
        throw Error( "session event wait failed" );
    }
    owner->stop();
    return 0;
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
  SessionOfferDecoder decoder;
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
  auto frame = make_session_offer( offer.server, offer.secret );
  write_frame( STDOUT_FILENO, frame.view() );
  // Destructors clear both parent-side representations before exit/SSH EOF.
}
}
int main( int argc, char** argv )
{
  try {
    if ( argc < 3 || std::string_view( argv[1] ) != "--session-profile"
         || std::string_view( argv[2] ) != SESSION_PROFILE )
      throw Error( "usage: phantom-mosh-server --session-profile phantom-mosh/session/draft-01" );
    RemotePolicy policy;
    // Until a terminal owner exists, an interrupted diagnostic client must not
    // leave a confirmed daemon alive indefinitely. The reusable owner defaults
    // to no idle expiry; this control-only executable defaults to one minute.
    policy.idle_ms = 60000;
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
