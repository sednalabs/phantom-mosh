// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Diagnostic SSH -> encrypted UDP -> close. This is not a terminal client.
#include "ssh_startup.h"
#include "session_channel.h"
#include <cerrno>
#include <poll.h>
#include <charconv>
#include <iostream>
#include <string>
using namespace phantom;
namespace {
void await_state( SessionChannel& channel, ChannelState wanted )
{
  while ( channel.state() != wanted ) {
    channel.service( session_time_ms() );
    if ( channel.state() == wanted ) break;
    if ( channel.state() == ChannelState::closed )
      throw Error( "UDP session confirmation timed out" );
    pollfd event { channel.fd(), POLLIN, 0 };
    const int ready = ::poll( &event, 1, channel.wait_ms( session_time_ms() ) );
    if ( ( ready < 0 && errno != EINTR ) || ( event.revents & POLLNVAL ) )
      throw Error( "UDP session wait failed" );
  }
  if ( wanted == ChannelState::closed && channel.end_reason() != ChannelEnd::peer_closed )
    throw Error( "UDP session close was not acknowledged" );
}
}
int main( int argc, char** argv )
{
  try {
    SshStartupOptions options;
    std::string override_host;
    std::uint16_t override_port = 0;
    for ( int i = 1; i < argc; ++i ) {
      const std::string arg( argv[i] );
      if ( arg == "--server" || arg == "--ssh-config" || arg == "--udp-host" || arg == "--udp-port" ) {
        if ( ++i == argc ) throw Error( "missing probe option value" );
        if ( arg == "--server" ) options.server_path = argv[i];
        if ( arg == "--ssh-config" ) options.config_path = argv[i];
        if ( arg == "--udp-host" ) override_host = argv[i];
        if ( arg == "--udp-port" ) {
          const std::string_view text( argv[i] );
          const auto parsed = std::from_chars( text.data(), text.data() + text.size(), override_port );
          if ( parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || !override_port )
            throw Error( "invalid UDP port override" );
        }
      } else {
        if ( arg.empty() || arg[0] == '-' || !options.destination.empty() )
          throw Error( "usage: phantom-mosh-probe [--server PATH] [--ssh-config FILE] [--udp-host IP] [--udp-port PORT] HOST" );
        options.destination = arg;
      }
    }
    if ( options.destination.empty() ) throw Error( "SSH destination required" );
    if ( !override_host.empty() ) UdpEndpoint::parse( override_host, 1 );
    auto offer = start_session_over_ssh( options );
    const auto peer = UdpEndpoint::parse( override_host.empty() ? offer.server.host() : override_host,
                                          override_port ? override_port : offer.server.port() );
    auto socket = SessionSocket::client_to( peer );
    auto channel = SessionChannel::client( std::move( socket ), peer, std::move( offer.secret ), session_time_ms() );
    await_state( *channel, ChannelState::active );
    channel->start_close( session_time_ms() );
    await_state( *channel, ChannelState::closed );
    std::cout << "Authenticated session confirmed over UDP and closed. No terminal was started.\n";
    return 0;
  } catch ( const std::exception& error ) { std::cerr << error.what() << '\n'; return 1; }
}
