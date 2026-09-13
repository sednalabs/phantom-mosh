// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "session_channel.h"
#include <algorithm>
#include <openssl/crypto.h>
#include <utility>

namespace phantom {
namespace {
void validate( const ChannelPolicy& p )
{
  if ( !p.connect_ms || p.connect_ms > 120000 || !p.close_ms || p.close_ms > 10000 || !p.retry_ms
       || p.retry_ms > 1000 || p.retry_max_ms < p.retry_ms || p.retry_max_ms > 30000 || p.revalidate_ms > 120000
       || !p.receive_budget || p.receive_budget > 64 )
    throw Error( "invalid channel policy" );
}
std::uint64_t remaining( std::uint64_t now, std::uint64_t start, std::uint64_t duration )
{
  return now - start >= duration ? 0 : duration - ( now - start );
}
}
ChannelBatch::~ChannelBatch()
{
  for ( auto& payload : data )
    if ( !payload.empty() )
      OPENSSL_cleanse( payload.data(), payload.size() );
}
SessionChannel::SessionChannel( SessionSocket&& socket, std::uint64_t now, ChannelPolicy policy )
  : socket_( std::make_unique<SessionSocket>( std::move( socket ) ) ), policy_( policy ), now_( now ),
    phase_started_( now ), retry_started_( now ), retry_interval_( policy.retry_ms )
{}
std::unique_ptr<SessionChannel> SessionChannel::client( SessionSocket&& socket,
                                                        UdpEndpoint peer,
                                                        Bootstrap&& secret,
                                                        std::uint64_t now,
                                                        ChannelPolicy policy,
                                                        Policy crypto )
{
  Bootstrap owned = std::move( secret );
  validate( policy );
  if ( socket.fd() < 0 || socket.local().ipv6() != peer.ipv6() )
    throw Error( "invalid client socket" );
  auto c = std::unique_ptr<SessionChannel>( new SessionChannel( std::move( socket ), now, policy ) );
  c->client_ = std::make_unique<SessionClient>( peer, std::move( owned ), now, crypto );
  return c;
}
std::unique_ptr<SessionChannel> SessionChannel::server( SessionSocket&& socket,
                                                        Bootstrap&& secret,
                                                        std::uint64_t now,
                                                        RemotePolicy lifetime,
                                                        ChannelPolicy policy,
                                                        Policy crypto )
{
  Bootstrap owned = std::move( secret );
  validate( policy );
  if ( socket.fd() < 0 )
    throw Error( "invalid server socket" );
  auto c = std::unique_ptr<SessionChannel>( new SessionChannel( std::move( socket ), now, policy ) );
  c->server_ = std::make_unique<RemoteSession>( std::move( owned ), now, lifetime, crypto );
  return c;
}
SessionChannel::~SessionChannel()
{
  stop();
}
void SessionChannel::finish( ChannelEnd reason ) noexcept
{
  if ( end_ != ChannelEnd::none )
    return;
  if ( client_ )
    client_->stop();
  if ( server_ )
    server_->stop();
  socket_.reset();
  end_ = reason;
  immediate_ = false;
}
void SessionChannel::stop() noexcept
{
  finish( ChannelEnd::stopped );
}
int SessionChannel::fd() const noexcept
{
  return socket_ ? socket_->fd() : -1;
}
ChannelState SessionChannel::state() const noexcept
{
  if ( end_ != ChannelEnd::none )
    return ChannelState::closed;
  if ( client_ ) {
    switch ( client_->state() ) {
      case ClientState::connecting:
        return ChannelState::connecting;
      case ClientState::active:
        return ChannelState::active;
      case ClientState::closing:
        return ChannelState::closing;
      case ClientState::closed:
        return ChannelState::closed;
    }
  }
  if ( server_ ) {
    switch ( server_->state() ) {
      case RemoteState::pending:
        return ChannelState::connecting;
      case RemoteState::active:
        return ChannelState::active;
      case RemoteState::draining:
        return ChannelState::closing;
      case RemoteState::closed:
        return ChannelState::closed;
    }
  }
  return ChannelState::closed;
}
std::optional<UdpEndpoint> SessionChannel::peer() const
{
  if ( end_ != ChannelEnd::none )
    return std::nullopt;
  if ( client_ )
    return client_->server();
  return server_ ? server_->peer() : std::nullopt;
}
void SessionChannel::check_time( std::uint64_t now ) const
{
  if ( now < now_ )
    throw Error( "channel clock moved backwards" );
}
void SessionChannel::advance_time( std::uint64_t now )
{
  check_time( now );
  now_ = now;
  if ( end_ != ChannelEnd::none )
    return;
  if ( client_ ) {
    client_->tick( now );
    const auto current = state();
    if ( current == ChannelState::connecting ) {
      const auto duration = established_ ? policy_.revalidate_ms : policy_.connect_ms;
      if ( duration && !remaining( now, phase_started_, duration ) )
        finish( established_ ? ChannelEnd::path_timeout : ChannelEnd::connect_timeout );
    }
    if ( current == ChannelState::closing && !remaining( now, phase_started_, policy_.close_ms ) )
      finish( ChannelEnd::close_timeout );
  } else {
    const auto was = state();
    server_->tick( now );
    if ( server_->state() == RemoteState::closed )
      finish( was == ChannelState::closing ? ChannelEnd::peer_closed : ChannelEnd::server_expired );
  }
}
int SessionChannel::wait_ms( std::uint64_t now ) const
{
  check_time( now );
  if ( state() == ChannelState::closed || immediate_ )
    return 0;
  std::uint64_t wait = 1000; // local key-retirement tick; no idle network traffic
  if ( server_ )
    wait = static_cast<std::uint64_t>( server_->wait_ms( now ) );
  else if ( state() == ChannelState::connecting || state() == ChannelState::closing ) {
    const auto duration = state() == ChannelState::closing ? policy_.close_ms
                          : established_                   ? policy_.revalidate_ms
                                                           : policy_.connect_ms;
    if ( duration )
      wait = std::min( wait, remaining( now, phase_started_, duration ) );
    wait = std::min( wait, retry_sent_ ? remaining( now, retry_started_, retry_interval_ ) : 0 );
  }
  return static_cast<int>( wait );
}
ChannelBatch SessionChannel::service( std::uint64_t now )
{
  check_time( now );
  ChannelBatch batch;
  try {
    advance_time( now );
    if ( end_ != ChannelEnd::none )
      return batch;
    immediate_ = false;
    // Reserve BEFORE consuming records. Even valid empty DATA is distinct from
    // control traffic or no data. No app callback executes inside this loop.
    batch.data.reserve( policy_.receive_budget );
    while ( batch.datagrams_read < policy_.receive_budget ) {
      auto input = socket_->receive_one();
      if ( !input.consumed )
        break;
      ++batch.datagrams_read;
      if ( !input.datagram )
        continue;
      auto& packet = *input.datagram;
      const auto before = state();
      if ( client_ ) {
        auto event = client_->receive( packet.peer, packet.bytes, now );
        if ( event.reply ) {
          socket_->send( client_->server(), *event.reply );
          retry_started_ = now;
          retry_interval_ = policy_.retry_ms;
          retry_sent_ = true;
        }
        if ( event.data )
          batch.data.push_back( std::move( *event.data ) );
        batch.activated |= before == ChannelState::connecting && state() == ChannelState::active;
        if ( state() == ChannelState::active )
          established_ = true;
        if ( client_->state() == ClientState::closed )
          finish( ChannelEnd::peer_closed );
      } else {
        auto event = server_->receive( packet.peer, packet.bytes, now );
        if ( event.reply )
          socket_->send( event.reply->peer, event.reply->datagram );
        if ( event.data )
          batch.data.push_back( std::move( *event.data ) );
        batch.activated |= event.activated;
        batch.migrated |= event.migrated;
      }
      if ( end_ != ChannelEnd::none )
        break;
    }
    batch.budget_exhausted = batch.datagrams_read == policy_.receive_budget;
    immediate_ = batch.budget_exhausted && end_ == ChannelEnd::none;
    if ( end_ == ChannelEnd::none && client_
         && ( state() == ChannelState::connecting || state() == ChannelState::closing )
         && ( !retry_sent_ || !remaining( now, retry_started_, retry_interval_ ) ) ) {
      // A late wakeup sends at most ONE fresh retry, never a catch-up burst.
      socket_->send( client_->server(), client_->retry( now ) );
      if ( retry_sent_ && established_ && state() == ChannelState::connecting )
        retry_interval_ = std::min( policy_.retry_max_ms, retry_interval_ * 2 );
      retry_started_ = now;
      retry_sent_ = true;
    }
    return batch;
  } catch ( ... ) {
    finish( ChannelEnd::failed );
    throw;
  }
}
bool SessionChannel::send( const Bytes& payload, std::uint64_t now )
{
  check_time( now );
  if ( payload.size() > max_payload() )
    throw Error( "channel payload exceeds datagram budget" );
  try {
    advance_time( now );
  } catch ( ... ) {
    finish( ChannelEnd::failed );
    throw;
  }
  if ( state() != ChannelState::active )
    throw Error( "channel is not active" );
  try {
    if ( client_ )
      return socket_->send( client_->server(), client_->send( payload, now ) );
    auto output = server_->send( payload, now );
    return socket_->send( output.peer, output.datagram );
  } catch ( ... ) {
    finish( ChannelEnd::failed );
    throw;
  }
}
void SessionChannel::start_close( std::uint64_t now )
{
  check_time( now );
  if ( !client_ )
    throw Error( "only the client initiates graceful session close" );
  try {
    advance_time( now );
  } catch ( ... ) {
    finish( ChannelEnd::failed );
    throw;
  }
  if ( state() == ChannelState::closed || state() == ChannelState::closing )
    return;
  if ( state() != ChannelState::active )
    throw Error( "channel is not active" );
  try {
    auto output = client_->close( now );
    phase_started_ = now;
    retry_started_ = now;
    retry_interval_ = policy_.retry_ms;
    retry_sent_ = true;
    socket_->send( client_->server(), output );
  } catch ( ... ) {
    finish( ChannelEnd::failed );
    throw;
  }
}
void SessionChannel::rebind( SessionSocket&& socket, std::uint64_t now )
{
  check_time( now );
  try {
    advance_time( now );
  } catch ( ... ) {
    finish( ChannelEnd::failed );
    throw;
  }
  if ( !client_ || !established_ || ( state() != ChannelState::active && state() != ChannelState::connecting )
       || socket.fd() < 0 || socket.local().ipv6() != client_->server().ipv6() )
    throw Error( "invalid channel rebind" );
  // Allocate before changing the live route or its crypto state.
  auto replacement = std::make_unique<SessionSocket>( std::move( socket ) );
  const bool was_active = state() == ChannelState::active;
  client_->revalidate_path();
  socket_.swap( replacement );
  now_ = now;
  if ( was_active )
    phase_started_ = now;
  retry_started_ = now;
  retry_interval_ = policy_.retry_ms;
  retry_sent_ = false;
  immediate_ = true;
}
} // namespace phantom
