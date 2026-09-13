// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "ssp_connection.h"
#include "ssp_test.h"
#include <iostream>
using namespace phantom;
static constexpr auto KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
static void connection( const char* host )
{
  auto server_socket = SessionSocket::bind( host );
  auto client_socket = SessionSocket::bind( host );
  const auto server_endpoint = server_socket.local();
  auto raw = SessionChannel::client( std::move( client_socket ), server_endpoint, Bootstrap::parse( KEY ), 0 );
  SspConnection server( SessionChannel::server( std::move( server_socket ), Bootstrap::parse( KEY ), 0 ), 0 );
  std::uint64_t now = 0;
  for ( ; now < 1000 && ( raw->state() != ChannelState::active || !server.get_has_remote_addr() ); ++now ) {
    raw->service( now );
    server.service( now );
  }
  CHECK( raw->state() == ChannelState::active && server.get_has_remote_addr() );
  CHECK( server.max_payload_size() == 1130 && SspConnection::MAX_FRAGMENT_CONTENTS == 1120 );
  std::string fragment( server.max_payload_size(), 'x' );
  auto frame = encode_ssp( { 1, 0, 0 }, fragment );
  CHECK( frame.size() == SessionChannel::max_payload() );
  CHECK( raw->send( frame, now ) );
  server.service( ++now );
  CHECK( server.pending() && server.wait_time() == 0 && server.recv() == fragment );
  CHECK( !server.pending() );
  bool empty_rejected = false;
  try { server.recv(); } catch ( const Network::NetworkException& e ) { empty_rejected = e.the_errno == EAGAIN; }
  CHECK( empty_rejected );
  for ( std::size_t n = 0; n < SSP_TIMING_BYTES + SspConnection::FRAGMENT_HEADER; ++n ) {
    CHECK( raw->send( Bytes( n ), now ) );
    server.service( ++now );
    CHECK( !server.pending() );
  }
  frame[0] = 99;
  CHECK( raw->send( frame, now ) );
  server.service( ++now );
  CHECK( !server.pending() );
  server.send( fragment );
  auto reply = raw->service( now );
  CHECK( reply.data.size() == 1 );
  SspStamp stamp;
  CHECK( decode_ssp( reply.data[0], stamp ) );
  CHECK( std::string( reply.data[0].begin() + SSP_TIMING_BYTES, reply.data[0].end() ) == fragment );
  bool oversized = false;
  try { server.send( fragment + 'x' ); } catch ( const Error& ) { oversized = true; }
  CHECK( oversized );
  // A retained batch cannot be silently overwritten by another receive pump.
  CHECK( raw->send( encode_ssp( { 2, 0, 0 }, fragment ), now ) );
  server.service( ++now );
  bool undrained = false;
  try { server.service( now ); } catch ( const Error& ) { undrained = true; }
  CHECK( undrained && server.recv() == fragment );
  server.stop();
  CHECK( server.state() == ChannelState::closed && server.fds().empty() );
}
int main()
{
  try {
    connection( "127.0.0.1" );
    connection( "::1" );
    std::cout << "PASS real UDP SSP admission, maximum fragment, malformed framing and bounded queue\n";
    return 0;
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
