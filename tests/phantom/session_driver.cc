// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Local process/UDP test driver. A frame on stdin is NOT SSH authentication.
#include "session_offer.h"
#include "session_udp.h"
#include "ssh_startup.h"
#include <array>
#include <iostream>
#include <openssl/crypto.h>
#include <string_view>
#include <unistd.h>
using namespace phantom;
namespace {
SessionOffer from_pipe()
{
  SessionOfferDecoder decoder;
  struct Buffer
  {
    std::array<char, SESSION_OFFER_MAX + 1> data {};
    ~Buffer() { OPENSSL_cleanse( data.data(), data.size() ); }
  } buffer;
  for ( ;; ) {
    const auto count = ::read( STDIN_FILENO, buffer.data.data(), buffer.data.size() );
    if ( count < 0 )
      throw Error( "test offer read failed" );
    if ( count == 0 )
      return decoder.finish();
    decoder.feed( { buffer.data.data(), static_cast<std::size_t>( count ) } );
    OPENSSL_cleanse( buffer.data.data(), buffer.data.size() );
  }
}
void await_state( SessionClient& client, SessionSocket& socket, ClientState wanted )
{
  const auto end = session_time_ms() + 2000;
  auto next = session_time_ms();
  while ( client.state() != wanted ) {
    const auto now = session_time_ms();
    if ( now >= end )
      throw Error( "test client timed out" );
    if ( now >= next ) {
      socket.send( client.server(), client.retry( now ) );
      next = now + 100;
    }
    socket.wait( 20 );
    for ( unsigned i = 0; i < 64; ++i ) {
      auto packet = socket.receive();
      if ( !packet )
        break;
      auto event = client.receive( packet->peer, packet->bytes, session_time_ms() );
      if ( event.reply )
        socket.send( client.server(), *event.reply );
    }
  }
}
}
int main( int argc, char** argv )
{
  try {
    const bool ssh = argc == 5 && std::string_view( argv[1] ) == "--ssh";
    const bool pipe
      = argc == 2 && ( std::string_view( argv[1] ) == "close" || std::string_view( argv[1] ) == "leave" );
    if ( !ssh && !pipe )
      throw Error( "invalid test driver arguments" );
    auto offer = [&]() {
      if ( pipe )
        return from_pipe();
      SshStartupOptions options;
      options.ssh_path = argv[2];
      options.config_path = argv[3];
      options.server_path = argv[4];
      options.destination = "fixture";
      return start_session_over_ssh( options );
    }();
    SessionClient client( offer.server, std::move( offer.secret ), session_time_ms() );
    auto socket = SessionSocket::client_to( offer.server );
    await_state( client, socket, ClientState::active );
    auto replacement = SessionSocket::client_to( offer.server );
    client.revalidate_path();
    await_state( client, replacement, ClientState::active );
    if ( ssh || std::string_view( argv[1] ) == "close" ) {
      replacement.send( client.server(), client.close( session_time_ms() ) );
      await_state( client, replacement, ClientState::closed );
    }
    std::cout << "PASS live session confirmation and port migration"
              << ( ssh || std::string_view( argv[1] ) == "close" ? ", closed\n" : ", left active\n" );
    return 0;
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
