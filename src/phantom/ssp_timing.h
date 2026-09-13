// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_SSP_TIMING_H
#define PHANTOM_MOSH_SSP_TIMING_H

#include "record.h"
#include <array>
#include <string>

namespace phantom {
// All fields are INSIDE authenticated, encrypted session DATA. This is an
// application framing version, not another clear record-protocol marker.
constexpr std::size_t SSP_TIMING_BYTES = 21;
struct SspStamp
{
  std::uint64_t serial = 0;
  std::uint64_t echo = 0;
  std::uint32_t hold_ms = 0;
};
Bytes encode_ssp( const SspStamp& stamp, const std::string& fragment );
bool decode_ssp( const Bytes& data, SspStamp& stamp ) noexcept;

// The serial identifies a local transmit timestamp in a bounded table. It is
// never inferred from receive order, wall time, or a truncated remote clock.
class SspTiming
{
public:
  static constexpr std::size_t HISTORY = 128;
  static constexpr std::uint64_t MAX_SAMPLE_MS = 10000;
  static constexpr std::uint32_t MAX_HOLD_MS = 1000;
  explicit SspTiming( std::uint64_t now ) : now_( now ) {}
  SspStamp prepare( std::uint64_t now ); // consumes a serial even if send fails
  void sent( const SspStamp& stamp, std::uint64_t now ); // only on socket success
  void received( const SspStamp& stamp, std::uint64_t now );
  void advance( std::uint64_t now );
  void reset_path() noexcept; // serials never rewind
  double srtt() const noexcept { return srtt_; }
  double rttvar() const noexcept { return variance_; }
  std::uint64_t timeout() const noexcept;
  std::uint64_t samples() const noexcept { return samples_; }
  bool has_sample() const noexcept { return sampled_; }

private:
  struct Pending
  {
    std::uint64_t serial = 0;
    std::uint64_t sent_at = 0;
  };
  std::array<Pending, HISTORY> pending_ {};
  std::uint64_t now_, next_ = 1, peer_highest_ = 0, echo_ = 0, echo_received_at_ = 0, samples_ = 0;
  double srtt_ = 1000, variance_ = 500;
  bool sampled_ = false;
};
} // namespace phantom
#endif
