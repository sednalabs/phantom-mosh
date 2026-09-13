// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_SSP_CONNECTION_H
#define PHANTOM_MOSH_SSP_CONNECTION_H

#include "session_channel.h"
#include "ssp_timing.h"
#include "src/network/network.h"
#include <deque>

namespace phantom {
// Connection backend for the inherited SSP sender/receiver, not an OCB tunnel.
// Construct both the channel and this adapter with the same monotonic clock.
class SspConnection
{
public:
  static constexpr std::size_t FRAGMENT_HEADER = 10;
  static constexpr std::size_t MAX_FRAGMENT = SESSION_MAX_DATA - SSP_TIMING_BYTES;
  static constexpr std::size_t MAX_FRAGMENT_CONTENTS = MAX_FRAGMENT - FRAGMENT_HEADER;
  SspConnection( std::unique_ptr<SessionChannel> channel, std::uint64_t now );
  ~SspConnection();
  SspConnection( const SspConnection& ) = delete;
  SspConnection& operator=( const SspConnection& ) = delete;
  SspConnection( SspConnection&& ) = delete;
  SspConnection& operator=( SspConnection&& ) = delete;

  // One bounded channel pump. Drain its admitted fragments before another pump.
  void service( std::uint64_t now );
  bool pending() const noexcept { return !received_.empty(); }
  int wait_time() const;
  std::uint64_t clock() const noexcept { return now_; }
  std::size_t max_payload_size() const noexcept { return MAX_FRAGMENT; }
  std::string recv();
  void send( const std::string& fragment );
  bool get_has_remote_addr() const noexcept { return channel_->state() == ChannelState::active; }
  const std::vector<int> fds() const;
  double get_SRTT() const noexcept { return timing_.srtt(); }
  std::uint64_t timeout() const noexcept { return timing_.timeout(); }
  const SspTiming& timing() const noexcept { return timing_; }
  std::string& get_send_error() noexcept { return send_error_; }
  void set_last_roundtrip_success( std::uint64_t sent_at );
  std::uint64_t last_roundtrip_success() const noexcept { return roundtrip_; }
  const Network::Addr& get_remote_addr() const noexcept { return peer_; }
  socklen_t get_remote_addr_len() const noexcept { return peer_size_; }
  ChannelState state() const noexcept { return channel_->state(); }
  ChannelEnd end_reason() const noexcept { return channel_->end_reason(); }
  void rebind( SessionSocket&& socket, std::uint64_t now );
  void start_close( std::uint64_t now );
  void stop() noexcept;

private:
  void clear_received() noexcept;
  void refresh_peer();
  std::unique_ptr<SessionChannel> channel_;
  SspTiming timing_;
  std::uint64_t now_, roundtrip_ = 0;
  std::deque<Bytes> received_;
  Network::Addr peer_ {};
  socklen_t peer_size_ = 0;
  std::string send_error_;
};
} // namespace phantom
#endif
