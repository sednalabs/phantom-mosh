// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "startup.h"
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <type_traits>
#include <utility>

using namespace phantom;
static constexpr auto KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
static constexpr auto PREFIX = "PHANTOM CONNECT phantom-mosh/v3/draft-01 server client ";
static void check( bool condition, const char* expression )
{
  if ( !condition )
    throw std::runtime_error( expression );
}
#define CHECK( x ) check( static_cast<bool>( x ), #x )

static std::string wire( std::string_view port = "60000", std::string_view key = KEY )
{
  return std::string( PREFIX ) + std::string( port ) + " " + std::string( key ) + "\n";
}
template<class F>
static void rejects( F&& f, std::string_view message = "invalid startup message" )
{
  try {
    f();
  } catch ( const Error& e ) {
    CHECK( std::string_view( e.what() ) == message );
    return;
  }
  throw std::runtime_error( "accepted invalid startup" );
}
static void invalid( std::string_view input )
{
  StartupDecoder decoder;
  rejects( [&] {
    decoder.feed( input );
    decoder.finish();
  } );
  rejects( [&] { decoder.feed( wire() ); } );
  rejects( [&] { decoder.finish(); } );
}
static void canonical_and_fragmented()
{
  static_assert( !std::is_copy_constructible_v<StartupFrame> );
  static_assert( !std::is_copy_constructible_v<StartupOffer> );
  static_assert( !std::is_move_constructible_v<StartupDecoder> );
  auto root = Bootstrap::parse( KEY );
  for ( unsigned int port : { 1U, 9U, 10U, 100U, 60000U, 65535U } ) {
    auto frame = make_startup_offer( static_cast<std::uint16_t>( port ), root );
    CHECK( frame.view() == wire( std::to_string( port ) ) );
    CHECK( frame.view().size() <= STARTUP_MAX_BYTES );
    for ( std::size_t split = 0; split <= frame.view().size(); ++split ) {
      StartupDecoder decoder;
      decoder.feed( {} );
      decoder.feed( frame.view().substr( 0, split ) );
      decoder.feed( frame.view().substr( split ) );
      auto parsed = decoder.finish();
      CHECK( parsed.server_port == port );
      auto encoded = parsed.secret.encode();
      CHECK( std::string_view( encoded.data(), encoded.size() ) == KEY );
      rejects( [&] { decoder.finish(); } );
      rejects( [&] { decoder.feed( {} ); } );
    }
  }
  auto longest = make_startup_offer( 65535, root );
  CHECK( longest.view().size() == STARTUP_MAX_BYTES );
  StartupDecoder bytewise;
  for ( char c : longest.view() )
    bytewise.feed( { &c, 1 } );
  CHECK( bytewise.finish().server_port == 65535 );
  rejects( [&] { make_startup_offer( 0, root ); }, "invalid startup port" );
}
static void secret_ownership_and_records()
{
  auto root = Bootstrap::random();
  auto frame = make_startup_offer( 60001, root );
  auto moved = std::move( frame );
  CHECK( frame.view().empty() );
  auto replaced = make_startup_offer( 60002, root );
  replaced = std::move( moved );
  CHECK( moved.view().empty() );
  StartupDecoder decoder;
  decoder.feed( replaced.view() );
  replaced.clear();
  CHECK( replaced.view().empty() );
  auto offer = decoder.finish();
  CHECK( offer.server_port == 60001 );
  Session client( Role::client, std::move( offer.secret ), 0 );
  Session server( Role::server, std::move( root ), 0 );
  CHECK( !offer.secret.valid() && !root.valid() );
  const Bytes payload { 1, 2, 3, 4 };
  auto opened = server.open( client.seal( payload, 0 ), 0 );
  CHECK( opened && opened->payload == payload );
  opened = client.open( server.seal( payload, 0 ), 0 );
  CHECK( opened && opened->payload == payload );
}
static void malformed_and_redacted()
{
  const auto valid = wire();
  for ( std::size_t n = 0; n < valid.size(); ++n )
    invalid( std::string_view( valid ).substr( 0, n ) );
  for ( auto port : { "0", "00", "01", "-1", "+1", "65536", "999999999999", "1.5", "", " 1", "1 " } )
    invalid( wire( port ) );
  for ( auto key : { std::string( 22, 'A' ),
                     std::string( 42, 'A' ),
                     std::string( 44, 'A' ),
                     std::string( 42, 'A' ) + "B",
                     std::string( 43, '-' ),
                     std::string( KEY ) + "=" } )
    invalid( wire( "60000", key ) );
  invalid( "MOSH CONNECT 60000 " + std::string( KEY ) + "\n" );
  invalid( "banner\n" + valid );
  invalid( valid + valid );
  invalid( valid + "\n" );
  invalid( valid + "trailer" );
  invalid( std::string( STARTUP_MAX_BYTES + 1, 'X' ) );
  for ( auto replacement :
        { "phantom-mosh/v2/draft-01", "phantom-mosh/v3/draft-02", "PHANTOM-MOSH/v3/draft-01" } ) {
    auto changed = valid;
    changed.replace( changed.find( "phantom-mosh/v3/draft-01" ), PROFILE_ID.size(), replacement );
    invalid( changed );
  }
  auto reversed = valid;
  reversed.replace( reversed.find( "server client" ), 13, "client server" );
  invalid( reversed );
  for ( unsigned int value = 0; value <= 255; ++value ) {
    if ( value >= 32 && value <= 126 )
      continue;
    auto changed = valid;
    changed[changed.size() - 2] = static_cast<char>( value );
    invalid( changed );
  }
  auto crlf = valid;
  crlf.insert( crlf.end() - 1, '\r' );
  invalid( crlf );
  // A complete first line is not success until EOF. Later bytes poison it.
  StartupDecoder duplicate;
  duplicate.feed( valid );
  rejects( [&] { duplicate.feed( valid ); } );
  rejects( [&] { duplicate.finish(); } );
}
static void mutation_roundtrips()
{
  std::mt19937 random( 0x504d4f53 );
  for ( unsigned int trial = 0; trial < 10000; ++trial ) {
    auto input = wire();
    const auto offset = static_cast<std::size_t>( random() ) % input.size();
    input[offset] = static_cast<char>( random() & 255U );
    StartupDecoder decoder;
    try {
      const auto split = static_cast<std::size_t>( random() ) % ( input.size() + 1 );
      decoder.feed( std::string_view( input ).substr( 0, split ) );
      decoder.feed( std::string_view( input ).substr( split ) );
      auto offer = decoder.finish();
      // Mutating a valid digit or base64 byte can legitimately change a field.
      // Every accepted result must still have one exact canonical encoding.
      CHECK( make_startup_offer( offer.server_port, offer.secret ).view() == input );
    } catch ( const Error& e ) {
      CHECK( std::string_view( e.what() ) == "invalid startup message" );
      rejects( [&] { decoder.finish(); } );
    }
  }
}
int main()
{
  try {
    canonical_and_fragmented();
    secret_ownership_and_records();
    malformed_and_redacted();
    mutation_roundtrips();
    std::cout << "PASS startup framing, ownership, record interoperability and rejection\n";
    return 0;
  } catch ( const std::exception& e ) {
    std::cerr << "FAIL " << e.what() << '\n';
    return 1;
  }
}
