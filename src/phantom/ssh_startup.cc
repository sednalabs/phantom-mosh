// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "ssh_startup.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern char** environ;
namespace phantom {
namespace {
void checked( bool ok )
{
  if ( !ok )
    throw Error( "SSH startup process operation failed" );
}
class Descriptor
{
public:
  explicit Descriptor( int fd ) : fd_( fd ) {}
  ~Descriptor()
  {
    if ( fd_ >= 0 )
      ::close( fd_ );
  }
  Descriptor( const Descriptor& ) = delete;
  Descriptor& operator=( const Descriptor& ) = delete;
  int get() const { return fd_; }
  void close()
  {
    if ( fd_ >= 0 ) {
      ::close( fd_ );
      fd_ = -1;
    }
  }
  void above_stdio()
  {
    if ( fd_ >= 0 && fd_ < 3 ) {
      const int replacement = ::fcntl( fd_, F_DUPFD_CLOEXEC, 3 );
      checked( replacement >= 0 );
      close();
      fd_ = replacement;
    }
  }

private:
  int fd_;
};
struct SpawnActions
{
  posix_spawn_file_actions_t value;
  SpawnActions() { checked( ::posix_spawn_file_actions_init( &value ) == 0 ); }
  ~SpawnActions() { ::posix_spawn_file_actions_destroy( &value ); }
};
struct SpawnAttributes
{
  posix_spawnattr_t value;
  SpawnAttributes() { checked( ::posix_spawnattr_init( &value ) == 0 ); }
  ~SpawnAttributes() { ::posix_spawnattr_destroy( &value ); }
};
struct Child
{
  pid_t pid = -1;
  bool owned = true;
  ~Child()
  {
    if ( pid <= 0 || !owned )
      return;
    // The unreaped group leader pins the ID until after group cleanup. WNOWAIT
    // below is essential: reaping first could let the kernel reuse that ID.
    ::kill( -pid, SIGKILL );
    while ( ::waitpid( pid, nullptr, 0 ) < 0 && errno == EINTR ) {}
  }
  bool exited_successfully()
  {
    siginfo_t info {};
    if ( ::waitid( P_PID, static_cast<id_t>( pid ), &info, WEXITED | WNOHANG | WNOWAIT ) < 0 ) {
      if ( errno == EINTR )
        return false;
      if ( errno == ECHILD )
        owned = false; // do not signal a possibly recycled PID
      throw Error( "SSH child ownership lost" );
    }
    if ( info.si_pid == 0 )
      return false;
    if ( info.si_code != CLD_EXITED || info.si_status != 0 )
      throw Error( "SSH authentication or remote startup failed" );
    return true;
  }
};
struct Buffer
{
  std::array<char, STARTUP_MAX_BYTES + 1> data {};
  ~Buffer() { clear(); }
  void clear() { OPENSSL_cleanse( data.data(), data.size() ); }
};
bool printable( const std::string& text )
{
  return !text.empty() && text.size() <= 4096
         && std::all_of( text.begin(), text.end(), []( unsigned char c ) { return c >= 32 && c < 127; } );
}
std::string quote( const std::string& text )
{
  std::string out = "'";
  for ( char c : text ) {
    if ( c == '\'' )
      out += "'\\''";
    else
      out += c;
  }
  return out + "'";
}
void validate( const SshStartupOptions& o )
{
  static constexpr auto allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@:%[]";
  if ( !printable( o.destination ) || o.destination.size() > 1024 || o.destination[0] == '-'
       || o.destination.find_first_not_of( allowed ) != std::string::npos || !printable( o.ssh_path )
       || o.ssh_path[0] != '/' || !printable( o.server_path ) || o.server_path[0] == '-'
       || ( !o.config_path.empty() && !printable( o.config_path ) ) || o.timeout.count() < 1
       || o.timeout.count() > 120000 || o.cancel_fd < -1 )
    throw Error( "invalid SSH startup configuration" );
  struct sigaction action
  {};
  checked( ::sigaction( SIGCHLD, nullptr, &action ) == 0 );
  if ( action.sa_handler != SIG_DFL || ( action.sa_flags & SA_NOCLDWAIT ) )
    throw Error( "SSH startup requires exclusive child reaping" );
}
void cancelled( int fd )
{
  if ( fd < 0 )
    return;
  pollfd event { fd, POLLIN, 0 };
  const int result = ::poll( &event, 1, 0 );
  if ( result < 0 && errno != EINTR )
    checked( false );
  if ( event.revents & POLLNVAL )
    throw Error( "invalid SSH cancellation descriptor" );
  if ( event.revents )
    throw Error( "SSH startup cancelled" );
}
} // namespace
StartupOffer start_over_ssh( const SshStartupOptions& options )
{
  validate( options );
  const auto deadline = std::chrono::steady_clock::now() + options.timeout;
  cancelled( options.cancel_fd );
  std::vector<std::string> args { options.ssh_path, "-n", "-T", "-a", "-x", "-S", "none" };
  for ( const char* setting : { "BatchMode=yes",
                                "StrictHostKeyChecking=yes",
                                "NumberOfPasswordPrompts=0",
                                "RequestTTY=no",
                                "ForkAfterAuthentication=no",
                                "SessionType=default",
                                "ControlMaster=no",
                                "ControlPersist=no",
                                "ClearAllForwardings=yes",
                                "ForwardAgent=no",
                                "ForwardX11=no",
                                "PermitLocalCommand=no",
                                "RemoteCommand=none",
                                "UpdateHostKeys=no",
                                "LogLevel=ERROR" } ) {
    args.emplace_back( "-o" );
    args.emplace_back( setting );
  }
  if ( !options.config_path.empty() ) {
    args.emplace_back( "-F" );
    args.push_back( options.config_path );
  }
  args.emplace_back( "--" );
  args.push_back( options.destination );
  args.push_back( "exec " + quote( options.server_path ) + " '--startup-profile' "
                  + quote( std::string( PROFILE_ID ) ) );
  std::vector<char*> argv;
  for ( auto& arg : args )
    argv.push_back( arg.data() );
  argv.push_back( nullptr );

  int ends[2];
  checked( ::pipe2( ends, O_CLOEXEC ) == 0 );
  Descriptor input( ends[0] ), output( ends[1] );
  input.above_stdio();
  output.above_stdio();
  Descriptor null( ::open( "/dev/null", O_RDWR | O_CLOEXEC ) );
  checked( null.get() >= 0 );
  null.above_stdio();
  checked( ::fcntl( input.get(), F_SETFL, O_NONBLOCK ) == 0 );
  SpawnActions actions;
  checked( ::posix_spawn_file_actions_adddup2( &actions.value, null.get(), STDIN_FILENO ) == 0 );
  checked( ::posix_spawn_file_actions_adddup2( &actions.value, output.get(), STDOUT_FILENO ) == 0 );
  checked( ::posix_spawn_file_actions_adddup2( &actions.value, null.get(), STDERR_FILENO ) == 0 );
  checked( ::posix_spawn_file_actions_addclosefrom_np( &actions.value, 3 ) == 0 );
  SpawnAttributes attr;
  sigset_t mask, defaults;
  ::sigemptyset( &mask );
  ::sigemptyset( &defaults );
  for ( int sig : { SIGPIPE, SIGINT, SIGTERM, SIGHUP, SIGQUIT } )
    ::sigaddset( &defaults, sig );
  checked( ::posix_spawnattr_setpgroup( &attr.value, 0 ) == 0 );
  checked( ::posix_spawnattr_setsigmask( &attr.value, &mask ) == 0 );
  checked( ::posix_spawnattr_setsigdefault( &attr.value, &defaults ) == 0 );
  checked( ::posix_spawnattr_setflags( &attr.value,
                                       POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF )
           == 0 );
  Child child;
  pid_t spawned = -1;
  checked( ::posix_spawn( &spawned, options.ssh_path.c_str(), &actions.value, &attr.value, argv.data(), environ )
           == 0 );
  child.pid = spawned;
  output.close();
  StartupDecoder decoder;
  Buffer buffer;
  bool eof = false;
  for ( ;; ) {
    cancelled( options.cancel_fd );
    const auto now = std::chrono::steady_clock::now();
    if ( now >= deadline )
      throw Error( "SSH startup timed out" );
    const bool success = child.exited_successfully();
    if ( success && eof )
      return decoder.finish();
    const auto left = std::chrono::ceil<std::chrono::milliseconds>( deadline - now ).count();
    pollfd events[2] { { eof ? -1 : input.get(), POLLIN, 0 }, { options.cancel_fd, POLLIN, 0 } };
    const int ready = ::poll( events, 2, static_cast<int>( std::min<decltype( left )>( left, 20 ) ) );
    if ( ready < 0 ) {
      if ( errno == EINTR )
        continue;
      checked( false );
    }
    cancelled( options.cancel_fd );
    if ( std::chrono::steady_clock::now() >= deadline )
      throw Error( "SSH startup timed out" );
    if ( events[0].revents & ( POLLERR | POLLNVAL ) )
      checked( false );
    if ( !( events[0].revents & ( POLLIN | POLLHUP ) ) )
      continue;
    const auto count = ::read( input.get(), buffer.data.data(), buffer.data.size() );
    if ( count < 0 ) {
      if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK )
        continue;
      checked( false );
    }
    if ( count == 0 ) {
      eof = true;
      input.close();
      continue;
    }
    decoder.feed( { buffer.data.data(), static_cast<std::size_t>( count ) } );
    buffer.clear();
  }
}
} // namespace phantom
