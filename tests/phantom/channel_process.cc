// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Test driver: stdin is a private fixture pipe, not an authentication mechanism.
#include "session_channel.h"
#include "session_offer.h"
#include <array>
#include <cerrno>
#include <iostream>
#include <openssl/crypto.h>
#include <poll.h>
#include <string_view>
#include <unistd.h>

using namespace phantom;
namespace {
SessionOffer read_offer()
{
  SessionOfferDecoder decoder;
  struct Buffer {
    std::array<char, SESSION_OFFER_MAX + 1> bytes {};
    ~Buffer() { OPENSSL_cleanse( bytes.data(), bytes.size() ); }
  } buffer;
  for ( ;; ) {
    const auto n = ::read( STDIN_FILENO, buffer.bytes.data(), buffer.bytes.size() );
    if ( n < 0 && errno == EINTR ) continue;
    if ( n < 0 ) throw Error( "test offer read failed" );
    if ( !n ) return decoder.finish();
    decoder.feed( { buffer.bytes.data(), static_cast<std::size_t>( n ) } );
    OPENSSL_cleanse( buffer.bytes.data(), buffer.bytes.size() );
  }
}
void await( SessionChannel& c, ChannelState wanted )
{
  for ( ;; ) {
    c.service( session_time_ms() );
    if ( c.state() == wanted ) return;
    if ( c.state() == ChannelState::closed ) throw Error( "test channel expired" );
    pollfd event { c.fd(), POLLIN, 0 };
    const int n = ::poll( &event, 1, c.wait_ms( session_time_ms() ) );
    if ( ( n < 0 && errno != EINTR ) || ( event.revents & POLLNVAL ) ) throw Error( "test wait failed" );
  }
}
}
int main( int argc, char** argv )
{
  try {
    if ( argc != 2 || ( std::string_view( argv[1] ) != "close" && std::string_view( argv[1] ) != "leave" ) )
      throw Error( "invalid test mode" );
    auto offer = read_offer(); auto socket = SessionSocket::client_to( offer.server );
    auto channel = SessionChannel::client( std::move( socket ), offer.server, std::move( offer.secret ), session_time_ms() );
    await( *channel, ChannelState::active );
    channel->rebind( SessionSocket::client_to( offer.server ), session_time_ms() );
    await( *channel, ChannelState::active );
    if ( std::string_view( argv[1] ) == "close" ) {
      channel->start_close( session_time_ms() ); await( *channel, ChannelState::closed );
      if ( channel->end_reason() != ChannelEnd::peer_closed ) throw Error( "test close was not acknowledged" );
    }
    std::cout << "PASS live session through channel pump, confirmed and migrated\n";
    return 0;
  } catch ( const std::exception& e ) { std::cerr << e.what() << '\n'; return 1; }
}
