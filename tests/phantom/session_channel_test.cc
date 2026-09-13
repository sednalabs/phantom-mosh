// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "session_channel.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <sys/socket.h>
#include <type_traits>
#include <unistd.h>

using namespace phantom;
namespace {
void check( bool value, const char* expression, int line )
{
  if ( !value )
    throw std::runtime_error( std::to_string( line ) + ": " + expression );
}
#define CHECK( x ) check( static_cast<bool>( x ), #x, __LINE__ )
constexpr auto KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
Bootstrap key()
{
  return Bootstrap::parse( KEY );
}
int fault_fd = -1;
int fault_errno = 0;
bool drop_once = false;
bool hold_once = false;
Bytes withheld;
sockaddr_storage withheld_peer {};
socklen_t withheld_size = 0;
std::size_t send_calls = 0;

template<class F>
void rejects( F f )
{
  try {
    f();
  } catch ( const Error& ) {
    return;
  }
  throw std::runtime_error( "expected rejection" );
}
ChannelPolicy channel_policy()
{
  ChannelPolicy p;
  p.retry_ms = 5;
  p.connect_ms = 500;
  p.close_ms = 50;
  p.receive_budget = 4;
  return p;
}
RemotePolicy remote_policy()
{
  RemotePolicy p;
  p.startup_ms = 500;
  p.path_ms = 50;
  p.drain_ms = 30;
  return p;
}
Policy crypto_policy()
{
  Policy p;
  p.rekey_packets = 3;
  p.hard_packets = 1000;
  return p;
}
struct Pair
{
  UdpEndpoint server_peer, client_peer;
  std::unique_ptr<SessionChannel> s, c;
  std::uint64_t now = 0;
  explicit Pair( const char* host = "127.0.0.1", ChannelPolicy policy = channel_policy() )
    : server_peer( UdpEndpoint::parse( host, 1 ) ), client_peer( server_peer )
  {
    auto ss = SessionSocket::bind( host );
    auto cs = SessionSocket::client_to( ss.local() );
    server_peer = ss.local();
    client_peer = cs.local();
    s = SessionChannel::server( std::move( ss ), key(), now, remote_policy(), policy, crypto_policy() );
    c = SessionChannel::client( std::move( cs ), server_peer, key(), now, policy, crypto_policy() );
  }
  void connect()
  {
    for ( unsigned n = 0; n < 100 && c->state() != ChannelState::active; ++n ) {
      c->service( now );
      s->service( now );
      c->service( now );
      ++now;
    }
    CHECK( c->state() == ChannelState::active && s->state() == ChannelState::active );
    CHECK( s->peer() == std::optional<UdpEndpoint>( client_peer ) );
  }
};
}
extern "C" ssize_t __real_sendto( int, const void*, size_t, int, const sockaddr*, socklen_t );
extern "C" ssize_t __wrap_sendto( int fd,
                                  const void* data,
                                  size_t size,
                                  int flags,
                                  const sockaddr* peer,
                                  socklen_t peer_size )
{
  ++send_calls;
  if ( fd == fault_fd ) {
    const auto* bytes = static_cast<const unsigned char*>( data );
    withheld.assign( bytes, bytes + size );
    CHECK( peer_size <= sizeof( withheld_peer ) );
    std::memcpy( &withheld_peer, peer, peer_size );
    withheld_size = peer_size;
    fault_fd = -1;
    if ( fault_errno ) {
      errno = fault_errno;
      fault_errno = 0;
      return -1;
    }
    if ( drop_once || hold_once ) {
      drop_once = false;
      hold_once = false;
      return static_cast<ssize_t>( size );
    }
  }
  return __real_sendto( fd, data, size, flags, peer, peer_size );
}
namespace {
void data_bidirectional( const char* host )
{
  Pair p( host );
  p.connect();
  static_assert( !std::is_copy_constructible_v<SessionChannel> && !std::is_move_constructible_v<SessionChannel> );
  CHECK( SessionChannel::max_payload() == 1151 );
  for ( unsigned n = 0; n < 60; ++n ) {
    Bytes payload( n % 2 ? 1151 : 0, static_cast<unsigned char>( n ) );
    CHECK( p.c->send( payload, p.now ) );
    auto server = p.s->service( p.now );
    CHECK( server.data.size() == 1 && server.data[0] == payload );
    CHECK( p.s->send( server.data[0], p.now ) );
    auto client = p.c->service( p.now );
    CHECK( client.data.size() == 1 && client.data[0] == payload );
    ++p.now;
  }
  rejects( [&] { p.c->send( Bytes( 1152 ), p.now ); } );
  CHECK( p.c->state() == ChannelState::active );
  CHECK( p.c->wait_ms( p.now ) == 1000 ); // no manufactured idle traffic
  const auto before = send_calls;
  p.c->service( p.now );
  p.s->service( p.now );
  CHECK( send_calls == before );
  rejects( [&] { p.c->service( p.now - 1 ); } );
  CHECK( p.c->state() == ChannelState::active );
}
void retries_and_expiry()
{
  auto peer = SessionSocket::bind( "127.0.0.1" );
  auto socket = SessionSocket::client_to( peer.local() );
  auto policy = channel_policy();
  policy.connect_ms = 100;
  auto c = SessionChannel::client( std::move( socket ), peer.local(), key(), 0, policy );
  CHECK( c->wait_ms( 0 ) == 0 );
  auto calls = send_calls;
  c->service( 0 );
  CHECK( send_calls == calls + 1 );
  CHECK( peer.receive() );
  for ( unsigned i = 0; i < 20; ++i )
    c->service( 0 );
  CHECK( !peer.receive() && c->wait_ms( 0 ) == 5 );
  c->service( 4 );
  CHECK( !peer.receive() );
  c->service( 90 );
  CHECK( peer.receive() && !peer.receive() ); // one, not eighteen, retries
  int fd = c->fd();
  c->service( 100 );
  CHECK( c->fd() == -1 && c->end_reason() == ChannelEnd::connect_timeout );
  CHECK( ::fcntl( fd, F_GETFD ) == -1 && errno == EBADF );
  c->stop();
  CHECK( c->wait_ms( 101 ) == 0 );

  auto ss = SessionSocket::bind( "127.0.0.1" );
  auto raw = SessionSocket::client_to( ss.local() );
  auto lifetime = remote_policy();
  lifetime.startup_ms = 10;
  auto s = SessionChannel::server( std::move( ss ), key(), 0, lifetime );
  s->service( 10 );
  CHECK( s->end_reason() == ChannelEnd::server_expired && s->fd() == -1 );
}
void handshake_loss_and_deadline()
{
  // Lose each leg sent after HELLO in turn. The same session, including its
  // packet-number allocator, must recover through the channel timer alone.
  for ( unsigned leg = 0; leg < 3; ++leg ) {
    Pair p;
    p.c->service( 0 );
    if ( leg == 0 ) {
      fault_fd = p.s->fd();
      drop_once = true;
    }
    p.s->service( 0 );
    if ( leg == 1 ) {
      fault_fd = p.c->fd();
      drop_once = true;
    }
    p.c->service( 0 );
    if ( leg == 2 ) {
      fault_fd = p.s->fd();
      drop_once = true;
    }
    p.s->service( 0 );
    for ( p.now = 1; p.now < 100 && p.c->state() != ChannelState::active; ++p.now ) {
      p.c->service( p.now );
      p.s->service( p.now );
      p.c->service( p.now );
    }
    CHECK( p.c->state() == ChannelState::active && p.s->state() == ChannelState::active );
  }
  Pair late;
  late.c->service( 0 );
  late.s->service( 0 );
  late.c->service( 0 );
  late.s->service( 0 );
  // An authentic READY is queued, but admission after the absolute deadline is
  // still forbidden. Parser/crypto success must not resurrect expired authority.
  late.c->service( 500 );
  CHECK( late.c->end_reason() == ChannelEnd::connect_timeout );
}
void discard_budget()
{
  Pair p;
  p.connect();
  auto attacker = SessionSocket::bind( "127.0.0.1" );
  // Oversized/truncated traffic must count as work, not look like an empty socket.
  sockaddr_in destination {};
  destination.sin_family = AF_INET;
  destination.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
  destination.sin_port = htons( p.server_peer.port() );
  Bytes too_large( MAX_DATAGRAM + 200, 0x55 );
  CHECK( __real_sendto( attacker.fd(),
                        too_large.data(),
                        too_large.size(),
                        0,
                        reinterpret_cast<sockaddr*>( &destination ),
                        sizeof( destination ) )
         > 0 );
  for ( unsigned n = 0; n < 6; ++n )
    CHECK( attacker.send( p.server_peer, Bytes( 49, 0x55 ) ) );
  CHECK( p.c->send( { 7 }, p.now ) );
  auto a = p.s->service( p.now );
  CHECK( a.datagrams_read == 4 && a.budget_exhausted && a.data.empty() );
  CHECK( p.s->wait_ms( p.now ) == 0 );
  auto b = p.s->service( p.now );
  CHECK( b.datagrams_read == 4 && b.data == std::vector<Bytes> { Bytes { 7 } } );
  p.s->service( p.now );
  CHECK( p.s->wait_ms( p.now ) > 0 );
}
void loss_and_fresh_nonce()
{
  Pair p;
  p.connect();
  fault_fd = p.c->fd();
  fault_errno = EAGAIN;
  CHECK( !p.c->send( { 1 }, p.now ) );
  const auto failed = withheld;
  CHECK( p.s->service( p.now ).data.empty() );
  fault_fd = p.c->fd();
  hold_once = true;
  CHECK( p.c->send( { 1 }, p.now ) );
  CHECK( withheld != failed );
  CHECK(
    __real_sendto(
      p.c->fd(), withheld.data(), withheld.size(), 0, reinterpret_cast<sockaddr*>( &withheld_peer ), withheld_size )
    > 0 );
  auto batch = p.s->service( p.now );
  CHECK( batch.data == std::vector<Bytes> { Bytes { 1 } } );
  fault_fd = p.c->fd();
  fault_errno = EBADF;
  rejects( [&] { p.c->send( { 2 }, p.now ); } );
  CHECK( p.c->fd() == -1 && p.c->end_reason() == ChannelEnd::failed );
}
void reordering_and_migration()
{
  Pair p;
  p.connect();
  fault_fd = p.c->fd();
  hold_once = true;
  CHECK( p.c->send( { 1 }, p.now ) );
  CHECK( p.c->send( { 2 }, p.now ) );
  CHECK(
    __real_sendto(
      p.c->fd(), withheld.data(), withheld.size(), 0, reinterpret_cast<sockaddr*>( &withheld_peer ), withheld_size )
    > 0 );
  auto batch = p.s->service( p.now );
  CHECK( batch.data.size() == 2 );
  CHECK( batch.data[0] == Bytes { 2 } && batch.data[1] == Bytes { 1 } );
  CHECK(
    __real_sendto(
      p.c->fd(), withheld.data(), withheld.size(), 0, reinterpret_cast<sockaddr*>( &withheld_peer ), withheld_size )
    > 0 );
  CHECK( p.s->service( p.now ).data.empty() );
  // Keep live crypto and counters across 180 days and a new local port.
  p.now += 180ULL * 24 * 60 * 60 * 1000;
  auto moved = SessionSocket::client_to( p.server_peer );
  const auto new_peer = moved.local();
  int old_fd = p.c->fd();
  p.c->rebind( std::move( moved ), p.now );
  CHECK( ::fcntl( old_fd, F_GETFD ) == -1 && errno == EBADF );
  CHECK( p.s->peer() == std::optional<UdpEndpoint>( p.client_peer ) );
  rejects( [&] { p.c->send( {}, p.now ); } );
  bool migrated = false;
  for ( unsigned n = 0; n < 50 && p.c->state() != ChannelState::active; ++n ) {
    p.c->service( p.now );
    auto r = p.s->service( p.now );
    migrated |= r.migrated;
    p.c->service( p.now );
    ++p.now;
  }
  CHECK( migrated && p.c->state() == ChannelState::active );
  CHECK( p.s->peer() == std::optional<UdpEndpoint>( new_peer ) );
  CHECK( p.c->send( { 3 }, p.now ) );
  CHECK( p.s->service( p.now ).data == std::vector<Bytes> { Bytes { 3 } } );
}
void established_outage_does_not_expire()
{
  Pair p;
  p.connect();
  p.c->rebind( SessionSocket::client_to( p.server_peer ), p.now );
  const auto started = p.now;
  // Every scheduled control transmission is lost for this period. Its retry
  // rate backs off, but an already established session must not be discarded.
  const auto calls = send_calls;
  for ( std::uint64_t dt = 0; dt <= 20000; dt += 5 ) {
    fault_fd = p.c->fd();
    drop_once = true;
    p.c->service( started + dt );
  }
  fault_fd = -1;
  drop_once = false;
  CHECK( p.c->state() == ChannelState::connecting && p.c->fd() >= 0 );
  CHECK( send_calls - calls < 30 );
  p.now = started + 180ULL * 24 * 60 * 60 * 1000;
  fault_fd = p.c->fd();
  drop_once = true;
  p.c->service( p.now );
  CHECK( p.c->state() == ChannelState::connecting );
  fault_fd = -1;
  drop_once = false;
  // A new local route can replace a previously unconfirmed one. Crypto state
  // survives; no fresh bootstrap or reset packet-number sequence is supplied.
  auto moved = SessionSocket::client_to( p.server_peer );
  const auto peer = moved.local();
  p.c->rebind( std::move( moved ), p.now );
  for ( unsigned n = 0; n < 100 && p.c->state() != ChannelState::active; ++n ) {
    p.c->service( p.now );
    p.s->service( p.now );
    p.c->service( p.now );
    ++p.now;
  }
  CHECK( p.c->state() == ChannelState::active && p.s->peer() == std::optional<UdpEndpoint>( peer ) );
  CHECK( p.c->send( { 4 }, p.now ) );
  CHECK( p.s->service( p.now ).data == std::vector<Bytes> { Bytes { 4 } } );
}
void explicit_recovery_deadline_is_fixed()
{
  auto policy = channel_policy();
  policy.revalidate_ms = 20;
  Pair p( "127.0.0.1", policy );
  p.connect();
  const auto started = p.now;
  p.c->rebind( SessionSocket::client_to( p.server_peer ), started );
  p.c->service( started );
  p.c->rebind( SessionSocket::client_to( p.server_peer ), started + 10 );
  p.c->service( started + 20 );
  CHECK( p.c->state() == ChannelState::closed && p.c->end_reason() == ChannelEnd::path_timeout );
}
void close_recovery_and_fixed_deadline()
{
  Pair p;
  p.connect();
  p.c->start_close( p.now );
  fault_fd = p.s->fd();
  drop_once = true;
  p.s->service( p.now );
  p.c->service( p.now );
  CHECK( p.s->state() == ChannelState::closing && p.c->state() == ChannelState::closing );
  for ( unsigned n = 0; n < 25 && p.c->state() != ChannelState::closed; ++n ) {
    p.c->service( ++p.now );
    p.s->service( p.now );
    p.c->service( p.now );
  }
  CHECK( p.c->end_reason() == ChannelEnd::peer_closed && p.c->fd() == -1 );
  p.now += 50;
  p.s->service( p.now );
  CHECK( p.s->end_reason() == ChannelEnd::peer_closed );
  CHECK( p.s->fd() == -1 );
  Pair lost;
  lost.connect();
  auto started = lost.now;
  lost.c->start_close( started );
  // Do not service the server: zero response, despite repeated local requests.
  for ( unsigned n = 1; n < 50; ++n )
    lost.c->start_close( started + n );
  lost.c->service( started + 50 );
  CHECK( lost.c->end_reason() == ChannelEnd::close_timeout && lost.c->fd() == -1 );
}
void policy_and_upper_clock()
{
  auto peer = SessionSocket::bind( "127.0.0.1" );
  auto local = SessionSocket::client_to( peer.local() );
  auto bad = channel_policy();
  bad.receive_budget = 65;
  auto secret = key();
  rejects( [&] { SessionChannel::client( std::move( local ), peer.local(), std::move( secret ), 0, bad ); } );
  CHECK( !secret.valid() && local.fd() >= 0 );
  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  auto c = SessionChannel::client( std::move( local ), peer.local(), key(), maximum - 500, channel_policy() );
  c->service( maximum - 500 );
  c->service( maximum - 1 );
  CHECK( c->state() == ChannelState::connecting );
  c->service( maximum );
  CHECK( c->end_reason() == ChannelEnd::connect_timeout );
}
}
int main()
{
  try {
    data_bidirectional( "127.0.0.1" );
    data_bidirectional( "::1" );
    retries_and_expiry();
    handshake_loss_and_deadline();
    discard_budget();
    loss_and_fresh_nonce();
    reordering_and_migration();
    established_outage_does_not_expire();
    explicit_recovery_deadline_is_fixed();
    close_recovery_and_fixed_deadline();
    policy_and_upper_clock();
    std::cout << "PASS channel: IPv4/IPv6 data, bounded pump, real send failures, fresh nonces, rekey, migration, "
                 "long sleep, close, expiry\n";
    return 0;
  } catch ( const std::exception& e ) {
    std::cerr << "FAIL " << e.what() << '\n';
    return 1;
  }
}
