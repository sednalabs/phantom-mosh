// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Real SSP and terminal models over real encrypted UDP. The linker interposer
// impairs only transport delivery; it never supplies SSP ACKs or remote state.
#include "src/statesync/completeterminal.h"
#include "src/statesync/user.h"
#include "ssp_test.h"
#include "ssp_transport.h"
#include <cerrno>
#include <clocale>
#include <cstring>
#include <iostream>
#include <optional>
#include <random>
#include <sys/socket.h>
#include <type_traits>

using namespace phantom;
using Client = SspTransport<Network::UserStream, Terminal::Complete>;
using Server = SspTransport<Terminal::Complete, Network::UserStream>;
static constexpr auto KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

namespace impairment {
enum class Mode
{
  reliable,
  chaotic,
  blackhole
};
static Mode mode = Mode::reliable;
static std::uint64_t calls = 0, drops = 0, duplicates = 0, reordered = 0, failures = 0, full_size = 0;
static bool over_budget = false;
struct Delayed
{
  int fd;
  Bytes data;
  int flags;
  sockaddr_storage address {};
  socklen_t size;
};
static std::optional<Delayed> delayed;
}
extern "C" ssize_t __real_sendto( int, const void*, size_t, int, const sockaddr*, socklen_t );
static void deliver_delayed()
{
  if ( impairment::delayed ) {
    auto packet = std::move( *impairment::delayed );
    impairment::delayed.reset();
    __real_sendto( packet.fd,
                   packet.data.data(),
                   packet.data.size(),
                   packet.flags,
                   reinterpret_cast<const sockaddr*>( &packet.address ),
                   packet.size );
  }
}
extern "C" ssize_t __wrap_sendto( int fd,
                                  const void* data,
                                  size_t size,
                                  int flags,
                                  const sockaddr* address,
                                  socklen_t address_size )
{
  using namespace impairment;
  ++calls;
  if ( size > MAX_DATAGRAM || address_size > sizeof( sockaddr_storage ) ) {
    over_budget = true;
    errno = EMSGSIZE;
    return -1;
  }
  full_size += size == MAX_DATAGRAM;
  if ( mode == Mode::blackhole || ( mode == Mode::chaotic && calls % 5 == 0 ) ) {
    ++drops;
    return static_cast<ssize_t>( size );
  }
  if ( mode == Mode::chaotic && calls % 17 == 0 ) {
    ++failures;
    errno = EAGAIN;
    return -1;
  }
  if ( mode == Mode::chaotic && calls % 11 == 0 && !delayed ) {
    const auto* bytes = static_cast<const unsigned char*>( data );
    Delayed packet { fd, Bytes( bytes, bytes + size ), flags, {}, address_size };
    std::memcpy( &packet.address, address, address_size );
    delayed = std::move( packet );
    ++reordered;
    return static_cast<ssize_t>( size );
  }
  const auto result = __real_sendto( fd, data, size, flags, address, address_size );
  if ( mode == Mode::chaotic && calls % 7 == 0 ) {
    __real_sendto( fd, data, size, flags, address, address_size );
    ++duplicates;
  }
  deliver_delayed();
  return result;
}
static void fragment_accounting()
{
  static_assert( std::is_same_v<Network::Transport<Network::UserStream, Terminal::Complete>,
                                Network::Transport<Network::UserStream, Terminal::Complete, Network::Connection>> );
  Network::Connection stock( "127.0.0.1", "0" );
  CHECK( stock.max_payload_size()
         == static_cast<std::size_t>( stock.get_MTU() - Network::Connection::ADDED_BYTES
                                      - Crypto::Session::ADDED_BYTES ) );
  CHECK( SspConnection::MAX_FRAGMENT + SSP_TIMING_BYTES + SESSION_HEADER + RECORD_OVERHEAD == MAX_DATAGRAM );
  CHECK( Network::Fragment::frag_header_len == SspConnection::FRAGMENT_HEADER );
  Network::Fragmenter fragmenter;
  TransportBuffers::Instruction instruction;
  instruction.set_protocol_version( Network::MOSH_PROTOCOL_VERSION );
  instruction.set_old_num( 0 );
  instruction.set_new_num( 1 );
  instruction.set_ack_num( 0 );
  instruction.set_throwaway_num( 0 );
  std::mt19937 random( 73021 );
  std::string contents;
  for ( std::size_t i = 0; i < 16384; ++i )
    contents += static_cast<char>( random() & 0xff );
  instruction.set_diff( contents );
  auto fragments = fragmenter.make_fragments( instruction, SspConnection::MAX_FRAGMENT );
  CHECK( fragments.size() > 10 );
  CHECK( fragments.front().tostring().size() == SspConnection::MAX_FRAGMENT );
  Network::FragmentAssembly assembly;
  bool complete = false;
  for ( auto i = fragments.rbegin(); i != fragments.rend(); ++i ) {
    CHECK( i->tostring().size() <= SspConnection::MAX_FRAGMENT );
    CHECK( i->contents.size() <= SspConnection::MAX_FRAGMENT_CONTENTS );
    complete = assembly.add_fragment( *i );
  }
  CHECK( complete && assembly.get_assembly().SerializeAsString() == instruction.SerializeAsString() );
  for ( std::size_t budget : { std::size_t { 0 }, std::size_t { 9 }, std::size_t { 10 } } ) {
    bool rejected = false;
    try {
      fragmenter.make_fragments( instruction, budget );
    } catch ( const std::length_error& ) {
      rejected = true;
    }
    CHECK( rejected );
  }
}
static void redraw( Terminal::Complete& terminal, unsigned seed )
{
  std::mt19937 random( seed );
  terminal.act( Parser::Resize( 100, 36 ) );
  terminal.act( "\x1b[2J\x1b[H" );
  for ( unsigned row = 1; row <= 34; ++row ) {
    std::string line = "\x1b[" + std::to_string( row ) + ";1H\x1b[" + std::to_string( 31 + row % 6 ) + "m";
    for ( unsigned col = 0; col < 95; ++col )
      line += static_cast<char>( 33 + random() % 90 );
    terminal.act( line );
  }
  terminal.act( "\x1b[0m\x1b[35;1HUTF-8: \xce\xbb \xd0\x96 \xe7\x95\x8c\x1b[36;1H" );
}
// Complete::operator== uses shared row identity to detect changes within one
// endpoint's copy-on-write history. Independently decoded peers need a semantic
// comparison, including presentation attributes, not shared allocation identity.
static bool same_terminal( const Terminal::Complete& a, const Terminal::Complete& b )
{
  const auto& left = a.get_fb();
  const auto& right = b.get_fb();
  if ( a.get_echo_ack() != b.get_echo_ack() || !( left.ds == right.ds )
       || left.get_window_title() != right.get_window_title() || left.get_clipboard() != right.get_clipboard()
       || left.get_bell_count() != right.get_bell_count() )
    return false;
  for ( int row = 0; row < left.ds.get_height(); ++row ) {
    for ( int col = 0; col < left.ds.get_width(); ++col ) {
      const auto& x = *left.get_cell( row, col );
      const auto& y = *right.get_cell( row, col );
      std::string x_text, y_text;
      x.print_grapheme( x_text );
      y.print_grapheme( y_text );
      if ( x_text != y_text || x.get_wide() != y.get_wide() || x.get_wrap() != y.get_wrap()
           || !( x.get_renditions() == y.get_renditions() ) || !( x.get_hyperlink() == y.get_hyperlink() ) )
        return false;
    }
  }
  return true;
}
static void convergence_oracle()
{
  Terminal::Complete source( 80, 24 ), independent( 80, 24 );
  CHECK( !( source == independent ) ); // distinct row allocations are expected
  CHECK( same_terminal( source, independent ) );
  redraw( source, 31 );
  independent.apply_string( source.diff_from( independent ) );
  CHECK( same_terminal( source, independent ) );
  // Negative controls keep the oracle sensitive to actual state corruption.
  for ( const std::string& change :
        { std::string( "\x1b[1;1H\xce\xbb" ), std::string( "\x1b[35;8H?" ), std::string( "\x1b[2;2H" ) } ) {
    auto changed = independent;
    changed.act( change );
    CHECK( !same_terminal( source, changed ) );
  }
  auto styled = independent;
  std::string first_cell;
  independent.get_fb().get_cell( 0, 0 )->print_grapheme( first_cell );
  styled.act( "\x1b[1;1H\x1b[7m" + first_cell + "\x1b[0m\x1b[36;1H" );
  CHECK( !same_terminal( source, styled ) );
  auto resized = independent;
  resized.act( Parser::Resize( 81, 25 ) );
  CHECK( !same_terminal( source, resized ) );
  auto acknowledged = independent;
  acknowledged.register_input_frame( 42, 1000 );
  acknowledged.set_echo_ack( 2000 );
  CHECK( !same_terminal( source, acknowledged ) );
}
// A user-space NAT model: the client retains its socket and destination while
// the server observes a new real UDP source port. No plaintext is inspected.
class NatRelay
{
  SessionSocket inside_;
  std::unique_ptr<SessionSocket> outside_;
  std::vector<std::unique_ptr<SessionSocket>> retired_;
  UdpEndpoint server_;
  std::optional<UdpEndpoint> client_;
  std::string host_;
  bool hold_next_ = false;
  std::optional<Bytes> held_;

public:
  NatRelay( const char* host, UdpEndpoint server )
    : inside_( SessionSocket::bind( host ) ),
      outside_( std::make_unique<SessionSocket>( SessionSocket::bind( host ) ) ), server_( server ), host_( host )
  {}
  const UdpEndpoint& endpoint() const { return inside_.local(); }
  const UdpEndpoint& mapped_endpoint() const { return outside_->local(); }
  void hold_next() { hold_next_ = true; }
  bool holding() const { return held_.has_value(); }
  void release_retired()
  {
    CHECK( held_ && !retired_.empty() );
    retired_.back()->send( server_, *held_ );
    held_.reset();
  }
  void remap()
  {
    auto replacement = std::make_unique<SessionSocket>( SessionSocket::bind( host_ ) );
    CHECK( replacement->local() != outside_->local() );
    retired_.push_back( std::move( outside_ ) );
    outside_ = std::move( replacement );
  }
  void pump()
  {
    for ( unsigned i = 0; i < 64; ++i ) {
      auto packet = inside_.receive();
      if ( !packet )
        break;
      client_ = packet->peer;
      if ( hold_next_ ) {
        held_ = std::move( packet->bytes );
        hold_next_ = false;
      } else
        outside_->send( server_, packet->bytes );
    }
    for ( unsigned i = 0; i < 64; ++i ) {
      auto packet = outside_->receive();
      if ( !packet )
        break;
      if ( packet->peer == server_ && client_ )
        inside_.send( *client_, packet->bytes );
    }
    // Expired mappings do not deliver replies, but retain descriptors so a
    // delayed interposed send cannot target a reused descriptor.
    for ( auto& socket : retired_ )
      for ( unsigned i = 0; i < 64 && socket->receive(); ++i ) {}
  }
};
static void convergence( const char* host, bool nat = false )
{
  using namespace impairment;
  delayed.reset();
  mode = Mode::chaotic;
  std::uint64_t now = 1000;
  Policy crypto;
  crypto.rekey_packets = 7;
  crypto.rekey_ms = 250;
  ChannelPolicy policy;
  policy.retry_ms = 20;
  policy.receive_budget = 16;
  auto server_socket = SessionSocket::bind( host );
  std::unique_ptr<NatRelay> relay;
  if ( nat )
    relay = std::make_unique<NatRelay>( host, server_socket.local() );
  const auto endpoint = relay ? relay->endpoint() : server_socket.local();
  auto client_socket = SessionSocket::client_to( endpoint );
  Network::UserStream initial_input;
  Terminal::Complete initial_terminal( 80, 24 );
  Client client(
    initial_input,
    initial_terminal,
    SessionChannel::client( std::move( client_socket ), endpoint, Bootstrap::parse( KEY ), now, policy, crypto ),
    now );
  auto server_channel
    = SessionChannel::server( std::move( server_socket ), Bootstrap::parse( KEY ), now, {}, policy, crypto );
  const auto* observed_server_channel = server_channel.get();
  Server server( initial_terminal, initial_input, std::move( server_channel ), now );
  Network::UserStream expected_input, delivered_input;
  Terminal::Complete displayed( 80, 24 );
  std::uint64_t last_input_frame = 0;
  auto step = [&] {
    now += 10;
    client.service( now );
    if ( relay )
      relay->pump();
    server.service( now );
    if ( relay )
      relay->pump();
    const auto diff = server.get_remote_diff();
    Network::UserStream input;
    input.apply_string( diff );
    delivered_input.apply_string( diff );
    for ( unsigned i = 0; i < input.size(); ++i ) {
      const auto* resize = dynamic_cast<const Parser::Resize*>( &input.get_action( i ) );
      if ( resize )
        server.get_current_state().act( *resize );
    }
    if ( server.get_remote_state_num() != last_input_frame ) {
      last_input_frame = server.get_remote_state_num();
      server.get_current_state().register_input_frame( last_input_frame, now );
    }
    server.get_current_state().set_echo_ack( now );
    displayed.apply_string( client.get_remote_diff() );
    CHECK( client.state() != ChannelState::closed && server.state() != ChannelState::closed );
    CHECK( client.wait_time() >= 0 && server.wait_time() >= 0 );
  };
  auto type = [&]( const std::string& text ) {
    for ( unsigned char c : text ) {
      client.get_current_state().push_back( Parser::UserByte( c ) );
      expected_input.push_back( Parser::UserByte( c ) );
    }
  };
  for ( unsigned i = 0;
        i < 900 && ( client.state() != ChannelState::active || server.state() != ChannelState::active );
        ++i )
    step();
  CHECK( client.state() == ChannelState::active && server.state() == ChannelState::active );
  redraw( server.get_current_state(), 31 );
  type( "exactly once across loss, duplication and key changes\n" );
  client.get_current_state().push_back( Parser::Resize( 100, 36 ) );
  expected_input.push_back( Parser::Resize( 100, 36 ) );
  for ( unsigned i = 0; i < 600; ++i ) {
    if ( i % 43 == 0 ) {
      type( "event-" + std::to_string( i ) + "\n" );
      server.get_current_state().act( "\x1b[36;1Hprogress " + std::to_string( i ) + "\x1b[K" );
    }
    step();
  }
  mode = Mode::reliable;
  deliver_delayed();
  auto converged = [&] {
    return delivered_input == expected_input && same_terminal( displayed, server.get_current_state() )
           && same_terminal( client.get_latest_remote_state().state, server.get_current_state() );
  };
  for ( unsigned i = 0; i < 2000 && !converged(); ++i )
    step();
  CHECK( converged() );
  CHECK( client.timing().samples() > 0 && server.timing().samples() > 0 );
  CHECK( client.get_sent_state_acked() > 0 && server.get_sent_state_acked() > 0 );

  if ( relay ) {
    const auto original_fds = client.fds();
    relay->hold_next();
    type( "queued on retired mapping\n" );
    for ( unsigned i = 0; i < 1000 && !relay->holding(); ++i )
      step();
    CHECK( relay->holding() );
    mode = Mode::chaotic;
    relay->remap();
    type( "transparent NAT remap without client notification\n" );
    redraw( server.get_current_state(), 43 );
    for ( unsigned i = 0; i < 600; ++i )
      step();
    mode = Mode::reliable;
    deliver_delayed();
    for ( unsigned i = 0; i < 3000 && !converged(); ++i )
      step();
    CHECK( client.fds() == original_fds );
    CHECK( converged() );
    CHECK( observed_server_channel->peer() == relay->mapped_endpoint() );
    relay->release_retired();
    type( "old path cannot roll the route back\n" );
    for ( unsigned i = 0; i < 3000 && !converged(); ++i )
      step();
    CHECK( converged() );
    CHECK( observed_server_channel->peer() == relay->mapped_endpoint() );
  }

  mode = Mode::blackhole;
  redraw( server.get_current_state(), 47 );
  type( "input retained during the outage\n" );
  const auto old_screen = client.get_latest_remote_state().state;
  for ( unsigned i = 0; i < 200; ++i )
    step();
  CHECK( client.get_latest_remote_state().state == old_screen );
  CHECK( !( old_screen == server.get_current_state() ) );
  now += 180ULL * 24 * 60 * 60 * 1000;
  if ( relay )
    relay->remap();
  else {
    client.rebind( SessionSocket::bind( host ), now );
    CHECK( !client.timing().has_sample() );
  }
  for ( unsigned i = 0; i < 300; ++i )
    step();
  CHECK( client.state() == ChannelState::connecting );
  mode = Mode::reliable;
  for ( unsigned i = 0; i < 3000 && ( client.state() != ChannelState::active || !converged() ); ++i )
    step();
  CHECK( client.state() == ChannelState::active && converged() );

  // SSP shutdown remains distinct from channel CLOSE. A transport close must
  // not cut off the final state acknowledgement.
  client.start_shutdown();
  for ( unsigned i = 0; i < 1000 && !client.shutdown_acknowledged(); ++i ) {
    now += 10;
    client.service( now );
    if ( relay )
      relay->pump();
    server.service( now );
    if ( relay )
      relay->pump();
  }
  CHECK( client.shutdown_acknowledged() && server.counterparty_shutdown_ack_sent() );
  client.start_channel_close( now );
  for ( unsigned i = 0; i < 1000 && client.state() != ChannelState::closed; ++i ) {
    now += 10;
    client.service( now );
    if ( relay )
      relay->pump();
    server.service( now );
    if ( relay )
      relay->pump();
  }
  CHECK( client.state() == ChannelState::closed && client.end_reason() == ChannelEnd::peer_closed );
  server.stop();
  delayed.reset();
  std::cout << "PASS " << host << ( nat ? " NAT relay" : " direct" )
            << " real terminal/resize/UTF-8/input convergence, outage, migration and shutdown\n";
}
int main()
{
  try {
    CHECK( std::setlocale( LC_ALL, "C.UTF-8" ) != nullptr );
    fragment_accounting();
    convergence_oracle();
    convergence( "127.0.0.1" );
    convergence( "::1" );
    convergence( "127.0.0.1", true );
    convergence( "::1", true );
    CHECK( !impairment::over_budget && impairment::full_size > 0 );
    CHECK( impairment::drops > 0 && impairment::duplicates > 0 && impairment::reordered > 0
           && impairment::failures > 0 );
    std::cout << "PASS byte budget and delivery impairment assertions\n";
    return 0;
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
