// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "remote_session.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <utility>

namespace phantom {
namespace {
using Token = std::array<unsigned char, 16>;
enum class Kind : unsigned char
{
  hello = 1,
  challenge,
  confirm,
  ready,
  data,
  close,
  closed
};
Token random_token()
{
  Token value {};
  if ( RAND_bytes( value.data(), static_cast<int>( value.size() ) ) != 1 )
    throw Error( "session challenge generation failed" );
  return value;
}
bool equal( const Token& a, const Token& b ) noexcept
{
  return CRYPTO_memcmp( a.data(), b.data(), a.size() ) == 0;
}
struct Message
{
  Kind kind;
  Token token;
};
std::optional<Message> decode( const Bytes& plain )
{
  if ( plain.size() < SESSION_HEADER )
    return std::nullopt;
  if ( plain[0] < static_cast<unsigned char>( Kind::hello )
       || plain[0] > static_cast<unsigned char>( Kind::closed ) )
    return std::nullopt;
  const auto kind = static_cast<Kind>( plain[0] );
  if ( kind != Kind::data && plain.size() != SESSION_HEADER )
    return std::nullopt;
  Token token {};
  std::copy_n( plain.begin() + 1, token.size(), token.begin() );
  return Message { kind, token };
}
Bytes encode( Kind kind, const Token& token, const Bytes& payload = {} )
{
  if ( payload.size() > SESSION_MAX_DATA )
    throw Error( "session payload exceeds record budget" );
  Bytes out( SESSION_HEADER + payload.size() );
  out[0] = static_cast<unsigned char>( kind );
  std::copy( token.begin(), token.end(), out.begin() + 1 );
  std::copy( payload.begin(), payload.end(), out.begin() + SESSION_HEADER );
  return out;
}
struct Wiped
{
  Bytes bytes;
  explicit Wiped( Bytes&& b ) : bytes( std::move( b ) ) {}
  ~Wiped()
  {
    if ( !bytes.empty() )
      OPENSSL_cleanse( bytes.data(), bytes.size() );
  }
};
Bytes seal( Session& crypto, Kind kind, const Token& token, std::uint64_t now, const Bytes& payload = {} )
{
  Wiped plain( encode( kind, token, payload ) );
  return crypto.seal( plain.bytes, now );
}
bool elapsed( std::uint64_t now, std::uint64_t start, std::uint64_t duration )
{
  return duration != 0 && now - start >= duration;
}
} // namespace

UdpEndpoint UdpEndpoint::parse( std::string_view host, std::uint16_t port )
{
  if ( host.empty() || host.size() >= INET6_ADDRSTRLEN || host.find( '\0' ) != std::string_view::npos || !port )
    throw Error( "invalid numeric UDP endpoint" );
  UdpEndpoint out;
  out.port_ = port;
  const std::string text( host );
  if ( inet_pton( AF_INET, text.c_str(), out.address_.data() ) == 1 ) {
    if ( out.address_[0] == 0 || out.address_[0] >= 224 )
      throw Error( "UDP endpoint must be unicast" );
  } else {
    out.ipv6_ = true;
    if ( inet_pton( AF_INET6, text.c_str(), out.address_.data() ) != 1 )
      throw Error( "invalid numeric UDP endpoint" );
    const auto& a = out.address_;
    const bool first_ten_zero = std::all_of( a.begin(), a.begin() + 10, []( unsigned char b ) { return b == 0; } );
    if ( std::all_of( a.begin(), a.end(), []( unsigned char b ) { return b == 0; } ) || a[0] == 0xff
         || ( a[0] == 0xfe && ( a[1] & 0xc0 ) == 0x80 ) || ( first_ten_zero && a[10] == 0xff && a[11] == 0xff ) )
      throw Error( "unsupported UDP address scope" );
  }
  return out;
}
std::string UdpEndpoint::host() const
{
  std::array<char, INET6_ADDRSTRLEN> text {};
  if ( !inet_ntop( ipv6_ ? AF_INET6 : AF_INET, address_.data(), text.data(), text.size() ) )
    throw Error( "UDP address conversion failed" );
  return text.data();
}
bool UdpEndpoint::operator==( const UdpEndpoint& other ) const noexcept
{
  return ipv6_ == other.ipv6_ && port_ == other.port_ && address_ == other.address_;
}

struct RemoteSession::Impl
{
  struct Candidate
  {
    UdpEndpoint peer;
    Token request, challenge;
    std::uint64_t started;
    ~Candidate() { OPENSSL_cleanse( challenge.data(), challenge.size() ); }
  };
  Session crypto;
  RemotePolicy policy;
  RemoteState state = RemoteState::pending;
  std::uint64_t created, now, last_activity, drain_started = 0;
  std::optional<UdpEndpoint> peer;
  std::unique_ptr<Candidate> candidate;
  Token proof {};
  Impl( Bootstrap&& root, std::uint64_t time, RemotePolicy p, Policy c )
    : crypto( Role::server, std::move( root ), time, c ), policy( p ), created( time ), now( time ),
      last_activity( time )
  {
    if ( !p.startup_ms || p.startup_ms > 120000 || !p.path_ms || p.path_ms > 120000 || !p.drain_ms
         || p.drain_ms > 10000 )
      throw Error( "invalid remote session lifetime policy" );
  }
  ~Impl() { stop(); }
  void stop() noexcept
  {
    crypto.close();
    candidate.reset();
    peer.reset();
    OPENSSL_cleanse( proof.data(), proof.size() );
    state = RemoteState::closed;
  }
  void tick( std::uint64_t time )
  {
    if ( time < now )
      throw Error( "session clock moved backwards" );
    now = time;
    if ( state == RemoteState::closed )
      return;
    crypto.tick( time );
    if ( ( state == RemoteState::pending && elapsed( time, created, policy.startup_ms ) )
         || ( state == RemoteState::active && elapsed( time, last_activity, policy.idle_ms ) )
         || ( state == RemoteState::draining && elapsed( time, drain_started, policy.drain_ms ) ) ) {
      stop();
      return;
    }
    if ( candidate && elapsed( time, candidate->started, policy.path_ms ) )
      candidate.reset();
  }
};
RemoteSession::RemoteSession( Bootstrap&& secret, std::uint64_t now, RemotePolicy policy, Policy crypto )
  : impl_( std::make_unique<Impl>( std::move( secret ), now, policy, crypto ) )
{}
RemoteSession::~RemoteSession() = default;
void RemoteSession::stop() noexcept
{
  impl_->stop();
}
void RemoteSession::tick( std::uint64_t now )
{
  impl_->tick( now );
}
RemoteState RemoteSession::state() const noexcept
{
  return impl_->state;
}
std::optional<UdpEndpoint> RemoteSession::peer() const
{
  return impl_->peer;
}
int RemoteSession::wait_ms( std::uint64_t now ) const
{
  const auto& s = *impl_;
  if ( now < s.now )
    throw Error( "session clock moved backwards" );
  if ( s.state == RemoteState::closed )
    return 0;
  std::uint64_t wait = 1000;
  auto limit = [&]( std::uint64_t start, std::uint64_t duration ) {
    if ( duration )
      wait = std::min( wait, now - start >= duration ? std::uint64_t { 0 } : duration - ( now - start ) );
  };
  if ( s.state == RemoteState::pending )
    limit( s.created, s.policy.startup_ms );
  if ( s.state == RemoteState::active )
    limit( s.last_activity, s.policy.idle_ms );
  if ( s.state == RemoteState::draining )
    limit( s.drain_started, s.policy.drain_ms );
  if ( s.candidate )
    limit( s.candidate->started, s.policy.path_ms );
  return static_cast<int>( wait );
}
RemoteEvent RemoteSession::receive( const UdpEndpoint& source, const Bytes& packet, std::uint64_t now )
{
  auto& s = *impl_;
  s.tick( now );
  if ( s.state == RemoteState::closed )
    return {};
  try {
    auto opened = s.crypto.open( packet, now );
    if ( !opened )
      return {};
    Wiped plain( std::move( opened->payload ) );
    const auto message = decode( plain.bytes );
    if ( !message )
      return {};
    const auto& m = *message;
    const bool active_source = s.peer && *s.peer == source && equal( m.token, s.proof );
    auto reply = [&]( Kind kind, const Token& token ) {
      auto wire = seal( s.crypto, kind, token, now );
      // Every control reply is the same size as the authenticated request.
      if ( wire.size() > packet.size() )
        throw Error( "session amplification invariant failed" );
      return Outbound { source, std::move( wire ) };
    };
    if ( s.state == RemoteState::draining ) {
      if ( m.kind == Kind::close && active_source )
        return { reply( Kind::closed, s.proof ), {}, false, false, false };
      return {};
    }
    if ( m.kind == Kind::hello && opened->newest ) {
      if ( s.candidate && s.candidate->peer == source && equal( s.candidate->request, m.token ) )
        return { reply( Kind::challenge, s.candidate->challenge ), {}, false, false, false };
      auto candidate
        = std::make_unique<Impl::Candidate>( Impl::Candidate { source, m.token, random_token(), now } );
      auto answer = reply( Kind::challenge, candidate->challenge );
      s.candidate = std::move( candidate );
      return { std::move( answer ), {}, false, false, false };
    }
    if ( m.kind == Kind::confirm ) {
      if ( s.candidate && s.candidate->peer == source && equal( s.candidate->challenge, m.token )
           && opened->newest ) {
        auto answer = reply( Kind::ready, m.token );
        const bool activation = s.state == RemoteState::pending;
        const bool migration = s.peer && *s.peer != source;
        s.peer = source;
        s.proof = m.token;
        s.candidate.reset();
        s.state = RemoteState::active;
        s.last_activity = now;
        return { std::move( answer ), {}, activation, migration, false };
      }
      // Lost READY recovery uses a freshly sealed CONFIRM, not a packet replay.
      if ( s.state == RemoteState::active && active_source )
        return { reply( Kind::ready, s.proof ), {}, false, false, false };
      return {};
    }
    if ( s.state != RemoteState::active || !active_source )
      return {};
    if ( m.kind == Kind::data ) {
      Bytes data( plain.bytes.begin() + SESSION_HEADER, plain.bytes.end() );
      if ( opened->newest )
        s.last_activity = now;
      return { {}, std::move( data ), false, false, false };
    }
    if ( m.kind == Kind::close && opened->newest ) {
      auto answer = reply( Kind::closed, s.proof );
      s.state = RemoteState::draining;
      s.drain_started = now;
      s.candidate.reset();
      return { std::move( answer ), {}, false, false, true };
    }
    return {};
  } catch ( ... ) {
    s.stop();
    throw;
  }
}
Outbound RemoteSession::send( const Bytes& payload, std::uint64_t now )
{
  auto& s = *impl_;
  s.tick( now );
  if ( s.state != RemoteState::active || !s.peer )
    throw Error( "remote session is not active" );
  if ( payload.size() > SESSION_MAX_DATA )
    throw Error( "session payload exceeds record budget" );
  try {
    return { *s.peer, seal( s.crypto, Kind::data, s.proof, now, payload ) };
  } catch ( ... ) {
    s.stop();
    throw;
  }
}

struct SessionClient::Impl
{
  const UdpEndpoint server;
  Session crypto;
  ClientState state = ClientState::connecting;
  Token request = random_token(), proof {};
  bool have_challenge = false;
  unsigned int retries = 0;
  Impl( UdpEndpoint address, Bootstrap&& root, std::uint64_t now, Policy policy )
    : server( address ), crypto( Role::client, std::move( root ), now, policy )
  {}
  void stop() noexcept
  {
    crypto.close();
    state = ClientState::closed;
    have_challenge = false;
    OPENSSL_cleanse( proof.data(), proof.size() );
    OPENSSL_cleanse( request.data(), request.size() );
  }
  void tick( std::uint64_t now )
  {
    if ( state == ClientState::closed )
      return;
    try {
      crypto.tick( now );
    } catch ( ... ) {
      stop();
      throw;
    }
  }
  Bytes encrypt( Kind kind, const Token& token, std::uint64_t now, const Bytes& data = {} )
  {
    try {
      return seal( crypto, kind, token, now, data );
    } catch ( ... ) {
      stop();
      throw;
    }
  }
  ~Impl() { stop(); }
};
SessionClient::SessionClient( UdpEndpoint server, Bootstrap&& secret, std::uint64_t now, Policy crypto )
  : impl_( std::make_unique<Impl>( server, std::move( secret ), now, crypto ) )
{}
SessionClient::~SessionClient() = default;
void SessionClient::tick( std::uint64_t now )
{
  impl_->tick( now );
}
void SessionClient::stop() noexcept
{
  impl_->stop();
}
ClientState SessionClient::state() const noexcept
{
  return impl_->state;
}
const UdpEndpoint& SessionClient::server() const noexcept
{
  return impl_->server;
}
Bytes SessionClient::retry( std::uint64_t now )
{
  auto& s = *impl_;
  if ( s.state == ClientState::closed )
    throw Error( "client session closed" );
  if ( s.state == ClientState::closing )
    return s.encrypt( Kind::close, s.proof, now );
  if ( s.state == ClientState::active )
    throw Error( "client session is already active" );
  // A stale challenge must not trap the client after the server retires it.
  // Periodically repeat HELLO with the same request identifier to recover.
  if ( s.have_challenge && ++s.retries % 4 != 0 )
    return s.encrypt( Kind::confirm, s.proof, now );
  return s.encrypt( Kind::hello, s.request, now );
}
void SessionClient::revalidate_path()
{
  auto& s = *impl_;
  if ( s.state == ClientState::closing || s.state == ClientState::closed )
    throw Error( "client session closing" );
  const auto request = random_token();
  s.request = request;
  s.have_challenge = false;
  s.retries = 0;
  s.state = ClientState::connecting;
  OPENSSL_cleanse( s.proof.data(), s.proof.size() );
}
ClientEvent SessionClient::receive( const UdpEndpoint& source, const Bytes& packet, std::uint64_t now )
{
  auto& s = *impl_;
  if ( source != s.server || s.state == ClientState::closed )
    return {};
  s.tick( now );
  auto opened = [&]() {
    try {
      return s.crypto.open( packet, now );
    } catch ( ... ) {
      s.stop();
      throw;
    }
  }();
  if ( !opened )
    return {};
  Wiped plain( std::move( opened->payload ) );
  const auto message = decode( plain.bytes );
  if ( !message )
    return {};
  const auto& m = *message;
  if ( m.kind == Kind::challenge && s.state == ClientState::connecting && opened->newest ) {
    auto answer = s.encrypt( Kind::confirm, m.token, now );
    s.proof = m.token;
    s.have_challenge = true;
    return { std::move( answer ), {} };
  }
  if ( !s.have_challenge || !equal( m.token, s.proof ) )
    return {};
  if ( m.kind == Kind::ready && s.state == ClientState::connecting && opened->newest )
    s.state = ClientState::active;
  if ( m.kind == Kind::closed && s.state == ClientState::closing )
    s.stop();
  if ( m.kind == Kind::data && s.state == ClientState::active )
    return { {}, Bytes( plain.bytes.begin() + SESSION_HEADER, plain.bytes.end() ) };
  return {};
}
Bytes SessionClient::send( const Bytes& payload, std::uint64_t now )
{
  auto& s = *impl_;
  if ( s.state != ClientState::active )
    throw Error( "client session is not active" );
  if ( payload.size() > SESSION_MAX_DATA )
    throw Error( "session payload exceeds record budget" );
  return s.encrypt( Kind::data, s.proof, now, payload );
}
Bytes SessionClient::close( std::uint64_t now )
{
  auto& s = *impl_;
  if ( s.state != ClientState::active && s.state != ClientState::closing )
    throw Error( "client session is not active" );
  auto packet = s.encrypt( Kind::close, s.proof, now );
  s.state = ClientState::closing;
  return packet;
}
} // namespace phantom
