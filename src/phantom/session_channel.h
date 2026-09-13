// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_SESSION_CHANNEL_H
#define PHANTOM_MOSH_SESSION_CHANNEL_H

#include "session_udp.h"
#include <memory>
#include <vector>

namespace phantom {
struct ChannelPolicy
{
  std::uint64_t connect_ms = 10000;
  std::uint64_t close_ms = 3000;
  std::uint64_t retry_ms = 200;
  std::uint64_t retry_max_ms = 5000;
  // Established sessions may outlive a network outage. Zero means no route-
  // recovery deadline; an explicit nonzero bound applies to the whole episode.
  std::uint64_t revalidate_ms = 0;
  std::size_t receive_budget = 32;
};
enum class ChannelState
{
  connecting,
  active,
  closing,
  closed
};
enum class ChannelEnd
{
  none,
  stopped,
  peer_closed,
  connect_timeout,
  path_timeout,
  close_timeout,
  server_expired,
  failed
};

// Owns received plaintext until moved out by the application. No receive queue
// survives a service call. A batch contains at most receive_budget datagrams.
struct ChannelBatch
{
  std::vector<Bytes> data;
  std::size_t datagrams_read = 0;
  bool budget_exhausted = false;
  bool activated = false;
  bool migrated = false;
  ChannelBatch() = default;
  ~ChannelBatch();
  ChannelBatch( ChannelBatch&& ) noexcept = default;
  ChannelBatch& operator=( ChannelBatch&& ) = delete;
  ChannelBatch( const ChannelBatch& ) = delete;
  ChannelBatch& operator=( const ChannelBatch& ) = delete;
};

// Single-threaded datagram bridge for an application event loop. It deliberately
// does not implement reliability, fragmentation, timestamps, SSP or terminal I/O.
class SessionChannel
{
public:
  static std::unique_ptr<SessionChannel> client( SessionSocket&& socket,
                                                 UdpEndpoint server,
                                                 Bootstrap&& secret,
                                                 std::uint64_t now_ms,
                                                 ChannelPolicy policy = {},
                                                 Policy crypto = {} );
  static std::unique_ptr<SessionChannel> server( SessionSocket&& socket,
                                                 Bootstrap&& secret,
                                                 std::uint64_t now_ms,
                                                 RemotePolicy lifetime = {},
                                                 ChannelPolicy policy = {},
                                                 Policy crypto = {} );
  ~SessionChannel();
  SessionChannel( const SessionChannel& ) = delete;
  SessionChannel& operator=( const SessionChannel& ) = delete;
  SessionChannel( SessionChannel&& ) = delete;
  SessionChannel& operator=( SessionChannel&& ) = delete;

  // Nonblocking, bounded receive work; retires keys and sends due control retries.
  // Call even while idle, using the same monotonic clock as wait_ms/send/close.
  ChannelBatch service( std::uint64_t now_ms );
  int wait_ms( std::uint64_t now_ms ) const;
  // Borrowed readiness descriptor; invalid after stop/rebind/destruction. Do not
  // close, read, change flags or transfer ownership. Closed channels return -1.
  int fd() const noexcept;
  ChannelState state() const noexcept;
  ChannelEnd end_reason() const noexcept { return end_; }
  // Client: authenticated target, even before reachability is confirmed.
  // Server: validated active route. Use state(), not peer(), for admission.
  std::optional<UdpEndpoint> peer() const;
  static constexpr std::size_t max_payload() noexcept { return SESSION_MAX_DATA; }

  // true means accepted by the local socket, NOT acknowledged by the peer.
  // false is a retryable local loss. No plaintext or sealed datagram is queued;
  // the application resends/recomputes with a fresh packet number.
  bool send( const Bytes& payload, std::uint64_t now_ms );
  // Client close is retried until authenticated acknowledgement or a fixed
  // deadline. Repeated calls cannot renew that deadline. Server shutdown uses stop.
  void start_close( std::uint64_t now_ms );
  // Client only: retain the exact crypto session while replacing its socket.
  // Application sends pause until return-path validation succeeds. A new local
  // socket must have the same address family; no address or protocol fallback.
  void rebind( SessionSocket&& socket, std::uint64_t now_ms );
  void stop() noexcept;

private:
  SessionChannel( SessionSocket&& socket, std::uint64_t now_ms, ChannelPolicy policy );
  void check_time( std::uint64_t now_ms ) const;
  void advance_time( std::uint64_t now_ms );
  void finish( ChannelEnd reason ) noexcept;
  std::unique_ptr<SessionSocket> socket_;
  std::unique_ptr<SessionClient> client_;
  std::unique_ptr<RemoteSession> server_;
  ChannelPolicy policy_;
  std::uint64_t now_, phase_started_, retry_started_;
  std::uint64_t retry_interval_;
  bool established_ = false;
  bool retry_sent_ = false;
  bool immediate_ = false;
  ChannelEnd end_ = ChannelEnd::none;
};
} // namespace phantom
#endif
