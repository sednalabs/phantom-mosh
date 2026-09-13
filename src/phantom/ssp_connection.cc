// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "ssp_connection.h"
#include <arpa/inet.h>
#include <cerrno>
#include <openssl/crypto.h>
#include <utility>

namespace phantom {
namespace {
void wipe( Bytes& data ) noexcept
{
  if ( !data.empty() )
    OPENSSL_cleanse( data.data(), data.size() );
}
}
SspConnection::SspConnection( std::unique_ptr<SessionChannel> channel, std::uint64_t now )
  : channel_( std::move( channel ) ), timing_( now ), now_( now )
{
  if ( !channel_ )
    throw Error( "SSP requires an owned session channel" );
  channel_->wait_ms( now ); // check the clock contract before using the channel
  refresh_peer();
}
SspConnection::~SspConnection()
{
  clear_received();
}
void SspConnection::clear_received() noexcept
{
  for ( auto& data : received_ )
    wipe( data );
  received_.clear();
}
void SspConnection::refresh_peer()
{
  peer_ = Network::Addr {};
  peer_size_ = 0;
  const auto endpoint = channel_->peer();
  if ( !endpoint )
    return;
  if ( endpoint->ipv6() ) {
    peer_.sin6.sin6_family = AF_INET6;
    peer_.sin6.sin6_port = htons( endpoint->port() );
    if ( inet_pton( AF_INET6, endpoint->host().c_str(), &peer_.sin6.sin6_addr ) != 1 )
      throw Error( "invalid SSP peer address" );
    peer_size_ = sizeof( peer_.sin6 );
  } else {
    peer_.sin.sin_family = AF_INET;
    peer_.sin.sin_port = htons( endpoint->port() );
    if ( inet_pton( AF_INET, endpoint->host().c_str(), &peer_.sin.sin_addr ) != 1 )
      throw Error( "invalid SSP peer address" );
    peer_size_ = sizeof( peer_.sin );
  }
}
void SspConnection::service( std::uint64_t now )
{
  if ( pending() )
    throw Error( "drain SSP fragments before servicing another batch" );
  timing_.advance( now );
  now_ = now;
  auto batch = channel_->service( now );
  if ( batch.activated || batch.migrated )
    timing_.reset_path();
  refresh_peer();
  try {
    for ( auto& data : batch.data ) {
      SspStamp stamp;
      if ( data.size() < SSP_TIMING_BYTES + FRAGMENT_HEADER || data.size() > SESSION_MAX_DATA
           || !decode_ssp( data, stamp ) )
        continue;
      timing_.received( stamp, now );
      received_.push_back( std::move( data ) );
    }
  } catch ( ... ) {
    clear_received();
    throw;
  }
}
int SspConnection::wait_time() const
{
  return pending() ? 0 : channel_->wait_ms( now_ );
}
const std::vector<int> SspConnection::fds() const
{
  const int fd = channel_->fd();
  return fd < 0 ? std::vector<int> {} : std::vector<int> { fd };
}
std::string SspConnection::recv()
{
  if ( !pending() )
    throw Network::NetworkException( "no admitted SSP fragment", EAGAIN );
  auto& data = received_.front();
  // Construct before removing the owned buffer, including allocation failure.
  std::string result( data.begin() + SSP_TIMING_BYTES, data.end() );
  wipe( data );
  received_.pop_front();
  return result;
}
void SspConnection::send( const std::string& fragment )
{
  if ( fragment.size() < FRAGMENT_HEADER || fragment.size() > MAX_FRAGMENT )
    throw Error( "SSP fragment exceeds its explicit datagram budget" );
  const auto stamp = timing_.prepare( now_ );
  auto data = encode_ssp( stamp, fragment );
  bool sent = false;
  try {
    sent = channel_->send( data, now_ );
  } catch ( ... ) {
    wipe( data );
    throw;
  }
  wipe( data );
  if ( sent ) {
    timing_.sent( stamp, now_ );
    send_error_.clear();
  } else {
    // Treat retryable local send failure as UDP loss, not a peer ACK. SSP owns
    // retransmission and state retention; no encrypted bytes are replayed here.
    send_error_ = "SSP datagram was not accepted by the local socket";
  }
}
void SspConnection::set_last_roundtrip_success( std::uint64_t sent_at )
{
  if ( sent_at > now_ )
    throw Error( "SSP acknowledgement timestamp is in the future" );
  roundtrip_ = std::max( roundtrip_, sent_at );
}
void SspConnection::rebind( SessionSocket&& socket, std::uint64_t now )
{
  timing_.advance( now );
  channel_->rebind( std::move( socket ), now );
  now_ = now;
  clear_received();
  timing_.reset_path();
  refresh_peer();
}
void SspConnection::start_close( std::uint64_t now )
{
  timing_.advance( now );
  channel_->start_close( now );
  now_ = now;
}
void SspConnection::stop() noexcept
{
  clear_received();
  timing_.reset_path();
  channel_->stop();
}
} // namespace phantom
