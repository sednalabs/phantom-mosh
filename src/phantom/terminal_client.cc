// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Experimental terminal frontend; deliberately no local prediction.
#include "src/statesync/user.h"
#include "src/terminal/terminaldisplay.h"
#include "ssh_startup.h"
#include "ssp_transport.h"
#include "terminal_state.h"
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <clocale>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

using namespace phantom;
namespace {
volatile sig_atomic_t stopping = 0;
volatile sig_atomic_t resized = 1;
volatile sig_atomic_t cancellation_writer = -1;
void signal_event( int signal )
{
  const int saved_errno = errno;
  if ( signal == SIGWINCH ) {
    resized = 1;
  } else {
    if ( !stopping )
      stopping = signal;
    const int fd = static_cast<int>( cancellation_writer );
    if ( fd >= 0 ) {
      const char byte = 'S';
      // The nonblocking pipe remains readable for the SSH supervisor until
      // cancellation unwinds. Repeated signals cannot block inside a handler.
      const auto ignored = ::write( fd, &byte, 1 );
      (void)ignored;
    }
  }
  errno = saved_errno;
}
class SignalLifetime
{
  int pipe_[2] = { -1, -1 };
  static constexpr int signals_[5] = { SIGWINCH, SIGTERM, SIGINT, SIGHUP, SIGPIPE };
  struct sigaction previous_[5] {};
  unsigned installed_ = 0;

public:
  SignalLifetime()
  {
    if ( ::pipe2( pipe_, O_CLOEXEC | O_NONBLOCK ) < 0 )
      throw Error( "cannot create SSH cancellation pipe" );
    cancellation_writer = pipe_[1];
    try {
      for ( int signal : signals_ ) {
        struct sigaction action
        {};
        action.sa_handler = signal == SIGPIPE ? SIG_IGN : signal_event;
        ::sigemptyset( &action.sa_mask );
        if ( ::sigaction( signal, &action, &previous_[installed_] ) < 0 )
          throw Error( "cannot configure terminal signals" );
        ++installed_;
      }
    } catch ( ... ) {
      restore();
      throw;
    }
  }
  ~SignalLifetime() { restore(); }
  SignalLifetime( const SignalLifetime& ) = delete;
  SignalLifetime& operator=( const SignalLifetime& ) = delete;
  int cancellation_fd() const noexcept { return pipe_[0]; }

private:
  void restore() noexcept
  {
    // This single-threaded frontend restores every handler before closing the
    // pipe, so a late handler can never write through a reused descriptor.
    while ( installed_ ) {
      --installed_;
      ::sigaction( signals_[installed_], &previous_[installed_], nullptr );
    }
    cancellation_writer = -1;
    for ( int& fd : pipe_ ) {
      if ( fd >= 0 )
        ::close( fd );
      fd = -1;
    }
  }
};
class LocalTerminal
{
  int input_flags_ = -1, output_flags_ = -1;
  bool raw_ = false;
  termios saved_ {};

public:
  LocalTerminal()
  {
    input_flags_ = ::fcntl( STDIN_FILENO, F_GETFL );
    output_flags_ = ::fcntl( STDOUT_FILENO, F_GETFL );
    try {
      if ( input_flags_ < 0 || output_flags_ < 0 || ::fcntl( STDIN_FILENO, F_SETFL, input_flags_ | O_NONBLOCK ) < 0
           || ::fcntl( STDOUT_FILENO, F_SETFL, output_flags_ | O_NONBLOCK ) < 0 )
        throw Error( "cannot configure terminal descriptors" );
      if ( ::isatty( STDIN_FILENO ) ) {
        if ( ::tcgetattr( STDIN_FILENO, &saved_ ) < 0 )
          throw Error( "cannot read local terminal mode" );
        auto raw = saved_;
        ::cfmakeraw( &raw );
        if ( ::tcsetattr( STDIN_FILENO, TCSANOW, &raw ) < 0 )
          throw Error( "cannot enter raw terminal mode" );
        raw_ = true;
      }
    } catch ( ... ) {
      restore();
      throw;
    }
  }
  ~LocalTerminal()
  {
    // Best-effort presentation reset on exceptional exits; termios restoration
    // below does not depend on a writable stdout or a cooperating consumer.
    static constexpr char reset[]
      = "\033[?1l\033[0m\033[?25h\033[?1003l\033[?1002l\033[?1001l\033[?1000l\033[?1015l\033[?1006l\033[?1005l";
    if ( output_flags_ >= 0 ) {
      const auto ignored = ::write( STDOUT_FILENO, reset, sizeof reset - 1 );
      (void)ignored;
    }
    restore();
  }
  LocalTerminal( const LocalTerminal& ) = delete;
  LocalTerminal& operator=( const LocalTerminal& ) = delete;

private:
  void restore() noexcept
  {
    if ( raw_ ) {
      while ( ::tcsetattr( STDIN_FILENO, TCSANOW, &saved_ ) < 0 && errno == EINTR ) {}
      raw_ = false;
    }
    if ( input_flags_ >= 0 )
      ::fcntl( STDIN_FILENO, F_SETFL, input_flags_ );
    if ( output_flags_ >= 0 )
      ::fcntl( STDOUT_FILENO, F_SETFL, output_flags_ );
  }
};
Parser::Resize window_size()
{
  winsize size {};
  if ( ::ioctl( STDIN_FILENO, TIOCGWINSZ, &size ) < 0 || !size.ws_col || !size.ws_row )
    return Parser::Resize( 80, 24 );
  // Bound framebuffer allocation and rendering work in this experimental frontend.
  return Parser::Resize( std::min( 300, static_cast<int>( size.ws_col ) ),
                         std::min( 100, static_cast<int>( size.ws_row ) ) );
}
using Client = SspTransport<Network::UserStream, TerminalState>;
int run( Client& transport )
{
  LocalTerminal local;
  Terminal::Display display( false );
  TerminalState drawn( 80, 24 );
  std::string pending = display.open();
  std::size_t offset = 0;
  bool initialized = false, eof = false, closing = false, reset_queued = false;
  std::uint64_t drawn_number = 0, stop_deadline = 0;
  constexpr std::size_t INPUT_LIMIT = 32768, OUTPUT_LIMIT = 4 * 1024 * 1024;
  for ( ;; ) {
    const auto now = session_time_ms();
    transport.service( now );
    if ( stopping ) {
      if ( !stop_deadline )
        stop_deadline = now + 5000;
      if ( now >= stop_deadline )
        throw Error( "local shutdown drain timed out" );
      if ( !transport.shutdown_in_progress() )
        transport.start_shutdown();
    }
    if ( !transport.shutdown_in_progress() && !eof && resized
         && transport.get_current_state().size() < INPUT_LIMIT ) {
      resized = 0;
      transport.get_current_state().push_back( window_size() );
    }
    // Coalesce redraws while stdout is backed up, retaining only one bounded frame.
    if ( pending.empty() && !reset_queued
         && ( !initialized || transport.get_remote_state_num() != drawn_number ) ) {
      const auto& newest = transport.get_latest_remote_state();
      auto frame = display.new_frame( initialized, drawn.get_fb(), newest.state.get_fb() );
      if ( frame.size() > OUTPUT_LIMIT )
        throw Error( "terminal redraw exceeds output bound" );
      pending = std::move( frame );
      drawn = newest.state;
      drawn_number = newest.num;
      initialized = true;
    }
    if ( !pending.empty() ) {
      const auto count = ::write( STDOUT_FILENO, pending.data() + offset, pending.size() - offset );
      if ( count > 0 ) {
        offset += static_cast<std::size_t>( count );
        if ( offset == pending.size() ) {
          pending.clear();
          offset = 0;
        }
      } else if ( count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR )
        throw Error( "local terminal output failed" );
    }
    const bool finished = transport.shutdown_acknowledged() || transport.counterparty_shutdown_ack_sent();
    if ( finished && pending.empty() && drawn_number == transport.get_remote_state_num() && !reset_queued ) {
      pending = display.close();
      reset_queued = true;
    }
    if ( finished && reset_queued && pending.empty() && !closing && transport.state() != ChannelState::closed ) {
      transport.start_channel_close( now );
      closing = true;
    }
    if ( !finished && transport.shutdown_ack_timed_out() )
      throw Error( "terminal shutdown acknowledgement timed out" );
    if ( transport.state() == ChannelState::closed ) {
      if ( !finished )
        throw Error( "terminal session closed before final state acknowledgement" );
      // A prior frame might have drained this iteration. Render any newer final
      // state before returning, even if the peer already closed its channel.
      if ( reset_queued && pending.empty() && drawn_number == transport.get_remote_state_num() ) {
        if ( stopping )
          return 128 + stopping;
        if ( transport.end_reason() != ChannelEnd::peer_closed )
          throw Error( "terminal channel close was not acknowledged" );
        return transport.get_latest_remote_state().state.exit_code();
      }
    }
    if ( !eof && !closing && !finished && !transport.shutdown_in_progress()
         && transport.get_current_state().size() < INPUT_LIMIT ) {
      char bytes[4096];
      const auto count = ::read(
        STDIN_FILENO, bytes, std::min( sizeof bytes, INPUT_LIMIT - transport.get_current_state().size() ) );
      if ( count > 0 ) {
        for ( ssize_t i = 0; i < count; ++i )
          transport.get_current_state().push_back( Parser::UserByte( bytes[i] ) );
      } else if ( count == 0 ) {
        // EOF on a pipe is not evidence that the remote command has completed.
        // Deliver terminal EOT once, then wait for server final state/shutdown.
        transport.get_current_state().push_back( Parser::UserByte( '\004' ) );
        eof = true;
      } else if ( errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR )
        throw Error( "local terminal input failed" );
    }
    std::vector<pollfd> events;
    for ( int fd : transport.fds() )
      events.push_back( { fd, POLLIN, 0 } );
    if ( !eof && !finished && !transport.shutdown_in_progress()
         && transport.get_current_state().size() < INPUT_LIMIT )
      events.push_back( { STDIN_FILENO, POLLIN, 0 } );
    if ( !pending.empty() )
      events.push_back( { STDOUT_FILENO, POLLOUT, 0 } );
    const int ready = ::poll( events.data(), events.size(), std::max( 0, std::min( 20, transport.wait_time() ) ) );
    if ( ready < 0 && errno != EINTR )
      throw Error( "terminal event wait failed" );
    for ( const auto& event : events )
      if ( event.revents & POLLNVAL )
        throw Error( "terminal descriptor closed" );
  }
}
}
int main( int argc, char** argv )
{
  try {
    if ( !std::setlocale( LC_ALL, "C.UTF-8" ) )
      throw Error( "C.UTF-8 locale required" );
    SshStartupOptions options;
    TerminalOptions terminal_options;
    options.server_path = "phantom-mosh-terminal-server";
    std::string override_host;
    std::uint16_t override_port = 0;
    for ( int i = 1; i < argc; ++i ) {
      const std::string arg( argv[i] );
      if ( arg == "--server" || arg == "--ssh-config" || arg == "--udp-host" || arg == "--udp-port"
           || arg == "--shell" || arg == "--term" ) {
        if ( ++i == argc )
          throw Error( "missing terminal option value" );
        if ( arg == "--shell" )
          terminal_options.shell = argv[i];
        if ( arg == "--term" )
          terminal_options.term = argv[i];
        if ( arg == "--server" )
          options.server_path = argv[i];
        if ( arg == "--ssh-config" )
          options.config_path = argv[i];
        if ( arg == "--udp-host" )
          override_host = argv[i];
        if ( arg == "--udp-port" ) {
          const std::string_view text( argv[i] );
          const auto parsed = std::from_chars( text.data(), text.data() + text.size(), override_port );
          if ( parsed.ec != std::errc {} || parsed.ptr != text.data() + text.size() || !override_port )
            throw Error( "invalid UDP port override" );
        }
      } else {
        if ( arg.empty() || arg[0] == '-' || !options.destination.empty() )
          throw Error( "usage: phantom-mosh-terminal [--server PATH] [--ssh-config FILE] [--udp-host IP] "
                       "[--udp-port PORT] [--shell /PATH] [--term TERM] HOST" );
        options.destination = arg;
      }
    }
    if ( options.destination.empty() )
      throw Error( "SSH destination required" );
    if ( !override_host.empty() )
      UdpEndpoint::parse( override_host, 1 );
    // Install cancellation before spawning SSH, but enter raw mode only once
    // SSH has authenticated and the terminal offer has been fully validated.
    SignalLifetime signals;
    options.cancel_fd = signals.cancellation_fd();
    auto offer = start_terminal_over_ssh( options, terminal_options );
    const auto peer = UdpEndpoint::parse( override_host.empty() ? offer.server.host() : override_host,
                                          override_port ? override_port : offer.server.port() );
    auto socket = SessionSocket::client_to( peer );
    auto channel
      = SessionChannel::client( std::move( socket ), peer, std::move( offer.secret ), session_time_ms() );
    Network::UserStream input;
    TerminalState terminal( 80, 24 );
    Client transport( input, terminal, std::move( channel ), session_time_ms() );
    return run( transport );
  } catch ( const std::exception& error ) {
    std::cerr << error.what() << '\n';
    return stopping ? 128 + stopping : 1;
  }
}
