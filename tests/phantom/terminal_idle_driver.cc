// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Actual SSH/PTY server regression: ACK-only SSP frames are not user input.
#include "src/statesync/completeterminal.h"
#include "src/statesync/user.h"
#include "ssh_startup.h"
#include "ssp_transport.h"
#include <algorithm>
#include <clocale>
#include <iostream>
#include <poll.h>
using namespace phantom;
using Client = SspTransport<Network::UserStream, Terminal::Complete>;
void require( bool value, const char* message )
{
  if ( !value )
    throw Error( message );
}
void step( Client& client )
{
  client.service( session_time_ms() );
  const auto fds = client.fds();
  if ( !fds.empty() ) {
    pollfd event { fds.front(), POLLIN, 0 };
    ::poll( &event, 1, std::max( 0, std::min( 10, client.wait_time() ) ) );
  }
}
int main( int argc, char** argv )
{
  try {
    require( argc == 4, "idle driver requires server, config and destination" );
    require( std::setlocale( LC_ALL, "C.UTF-8" ) != nullptr, "UTF-8 required" );
    SshStartupOptions options;
    options.server_path = argv[1];
    options.config_path = argv[2];
    options.destination = argv[3];
    auto offer = start_terminal_over_ssh( options );
    auto socket = SessionSocket::client_to( offer.server );
    const auto now = session_time_ms();
    Network::UserStream input;
    Terminal::Complete screen( 80, 24 );
    Client client( input,
                   screen,
                   SessionChannel::client( std::move( socket ), offer.server, std::move( offer.secret ), now ),
                   now );
    client.get_current_state().push_back( Parser::Resize( 80, 24 ) );
    const auto deadline = now + 5000;
    while ( client.get_latest_remote_state().state.get_echo_ack() == 0 ) {
      require( session_time_ms() < deadline && client.state() != ChannelState::closed,
               "initial real input was not echo-acknowledged" );
      step( client );
    }
    const auto settle = session_time_ms() + 1000;
    while ( session_time_ms() < settle )
      step( client );
    const auto echo = client.get_latest_remote_state().state.get_echo_ack();
    const auto idle_until = session_time_ms() + 3500;
    while ( session_time_ms() < idle_until ) {
      step( client );
      require( client.get_latest_remote_state().state.get_echo_ack() == echo,
               "ACK-only SSP frame became terminal input (idle feedback loop)" );
    }
    client.start_shutdown();
    const auto shutdown_until = session_time_ms() + 5000;
    while ( !client.shutdown_acknowledged() ) {
      require( session_time_ms() < shutdown_until, "idle driver SSP close timed out" );
      step( client );
    }
    client.start_channel_close( session_time_ms() );
    while ( client.state() != ChannelState::closed ) {
      require( session_time_ms() < shutdown_until, "idle driver channel close timed out" );
      step( client );
    }
    require( client.end_reason() == ChannelEnd::peer_closed, "idle driver close unacknowledged" );
    std::cout << "PASS actual terminal echo ACK remains stable across idle SSP ACK frames\n";
    return 0;
  } catch ( const std::exception& error ) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
