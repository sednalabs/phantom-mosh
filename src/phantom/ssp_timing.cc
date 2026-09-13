// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "ssp_timing.h"
#include <algorithm>
#include <cmath>
#include <limits>

namespace phantom {
namespace {
void put( unsigned char* out, std::uint64_t value, std::size_t size )
{
  for ( std::size_t i = size; i != 0; --i ) {
    out[i - 1] = static_cast<unsigned char>( value );
    value >>= 8;
  }
}
std::uint64_t get( const unsigned char* in, std::size_t size )
{
  std::uint64_t result = 0;
  for ( std::size_t i = 0; i < size; ++i )
    result = ( result << 8 ) | in[i];
  return result;
}
}
Bytes encode_ssp( const SspStamp& stamp, const std::string& fragment )
{
  if ( !stamp.serial || stamp.hold_ms > SspTiming::MAX_HOLD_MS || ( !stamp.echo && stamp.hold_ms ) )
    throw Error( "invalid SSP timestamp envelope" );
  Bytes out( SSP_TIMING_BYTES + fragment.size() );
  out[0] = 1;
  put( out.data() + 1, stamp.serial, 8 );
  put( out.data() + 9, stamp.echo, 8 );
  put( out.data() + 17, stamp.hold_ms, 4 );
  std::copy( fragment.begin(), fragment.end(), out.begin() + SSP_TIMING_BYTES );
  return out;
}
bool decode_ssp( const Bytes& data, SspStamp& stamp ) noexcept
{
  if ( data.size() < SSP_TIMING_BYTES || data[0] != 1 )
    return false;
  const SspStamp candidate { get( data.data() + 1, 8 ), get( data.data() + 9, 8 ),
                            static_cast<std::uint32_t>( get( data.data() + 17, 4 ) ) };
  if ( !candidate.serial || candidate.hold_ms > SspTiming::MAX_HOLD_MS
       || ( !candidate.echo && candidate.hold_ms ) )
    return false;
  stamp = candidate;
  return true;
}
void SspTiming::reset_path() noexcept
{
  pending_.fill( Pending {} );
  echo_ = 0;
  sampled_ = false;
  srtt_ = 1000;
  variance_ = 500;
}
void SspTiming::advance( std::uint64_t now )
{
  if ( now < now_ )
    throw Error( "SSP clock moved backwards" );
  if ( now - now_ > MAX_SAMPLE_MS )
    reset_path();
  now_ = now;
}
SspStamp SspTiming::prepare( std::uint64_t now )
{
  advance( now );
  if ( next_ == std::numeric_limits<std::uint64_t>::max() )
    throw Error( "SSP timestamp serial exhausted" );
  SspStamp stamp { next_++, 0, 0 };
  if ( echo_ && now - echo_received_at_ <= MAX_HOLD_MS ) {
    stamp.echo = echo_;
    stamp.hold_ms = static_cast<std::uint32_t>( now - echo_received_at_ );
  }
  return stamp;
}
void SspTiming::sent( const SspStamp& stamp, std::uint64_t now )
{
  advance( now );
  if ( !stamp.serial || stamp.serial != next_ - 1 )
    throw Error( "SSP timestamp ownership violation" );
  pending_[stamp.serial % HISTORY] = { stamp.serial, now };
  if ( stamp.echo == echo_ )
    echo_ = 0;
}
void SspTiming::received( const SspStamp& stamp, std::uint64_t now )
{
  advance( now );
  if ( !stamp.serial || stamp.hold_ms > MAX_HOLD_MS || ( !stamp.echo && stamp.hold_ms ) )
    throw Error( "invalid SSP timestamp envelope" );
  if ( stamp.serial > peer_highest_ ) {
    peer_highest_ = stamp.serial;
    echo_ = stamp.serial;
    echo_received_at_ = now;
  }
  if ( !stamp.echo )
    return;
  auto& pending = pending_[stamp.echo % HISTORY];
  if ( pending.serial != stamp.echo )
    return; // unknown, evicted, duplicate or failed local transmission
  const auto elapsed = now - pending.sent_at;
  pending.serial = 0; // a local sample can be consumed only once
  if ( elapsed > MAX_SAMPLE_MS || stamp.hold_ms > elapsed )
    return;
  const double sample = static_cast<double>( elapsed - stamp.hold_ms );
  if ( !sampled_ ) {
    srtt_ = sample;
    variance_ = sample / 2;
    sampled_ = true;
  } else {
    variance_ = 0.75 * variance_ + 0.25 * std::fabs( srtt_ - sample );
    srtt_ = 0.875 * srtt_ + 0.125 * sample;
  }
  ++samples_;
}
std::uint64_t SspTiming::timeout() const noexcept
{
  // Preserve Mosh's bounded retry cadence rather than interpreting this as TCP.
  return static_cast<std::uint64_t>( std::clamp( std::ceil( srtt_ + 4 * variance_ ), 50.0, 1000.0 ) );
}
} // namespace phantom
