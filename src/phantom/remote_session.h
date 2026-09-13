// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_REMOTE_SESSION_H
#define PHANTOM_MOSH_REMOTE_SESSION_H

#include "record.h"
#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace phantom {
// This application profile is selected inside authenticated SSH startup. It
// uses draft-01 records without changing their key schedule or wire format.
constexpr std::string_view SESSION_PROFILE = "phantom-mosh/session/draft-01";
constexpr std::size_t SESSION_HEADER = 17;
constexpr std::size_t SESSION_MAX_DATA = MAX_PAYLOAD - SESSION_HEADER;

// A numeric unicast address, not an SSH alias or a DNS name. Scope-dependent
// link-local IPv6 and IPv4-mapped IPv6 are deliberately unsupported for now.
class UdpEndpoint
{
public:
  static UdpEndpoint parse( std::string_view host, std::uint16_t port );
  std::string host() const;
  std::uint16_t port() const noexcept { return port_; }
  bool ipv6() const noexcept { return ipv6_; }
  bool operator==( const UdpEndpoint& other ) const noexcept;
  bool operator!=( const UdpEndpoint& other ) const noexcept { return !( *this == other ); }

private:
  UdpEndpoint() = default;
  std::array<unsigned char, 16> address_ {};
  std::uint16_t port_ = 0;
  bool ipv6_ = false;
};

struct RemotePolicy
{
  std::uint64_t startup_ms = 10000;
  std::uint64_t path_ms = 3000;
  std::uint64_t drain_ms = 1000;
  // Zero deliberately preserves Mosh-like long network disconnections. The
  // future terminal owner is responsible for ending a confirmed live session.
  std::uint64_t idle_ms = 0;
};
enum class RemoteState { pending, active, draining, closed };
struct Outbound
{
  UdpEndpoint peer;
  Bytes datagram;
};
struct RemoteEvent
{
  std::optional<Outbound> reply;
  std::optional<Bytes> data;
  bool activated = false;
  bool migrated = false;
  bool closing = false;
};

class RemoteSession
{
public:
  RemoteSession( Bootstrap&& secret, std::uint64_t now_ms, RemotePolicy policy = {}, Policy crypto = {} );
  ~RemoteSession();
  RemoteSession( const RemoteSession& ) = delete;
  RemoteSession& operator=( const RemoteSession& ) = delete;
  RemoteEvent receive( const UdpEndpoint& source, const Bytes& packet, std::uint64_t now_ms );
  Outbound send( const Bytes& payload, std::uint64_t now_ms );
  void tick( std::uint64_t now_ms );
  void stop() noexcept;
  RemoteState state() const noexcept;
  std::optional<UdpEndpoint> peer() const;
  // Timer bound for an event loop. Input is the same trusted monotonic clock.
  int wait_ms( std::uint64_t now_ms ) const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

enum class ClientState { connecting, active, closing, closed };
struct ClientEvent
{
  std::optional<Bytes> reply;
  std::optional<Bytes> data;
};
// A small control-plane adapter, not a terminal transport. It requires the
// endpoint from an authenticated SessionOffer (or a trusted explicit override).
class SessionClient
{
public:
  SessionClient( UdpEndpoint server, Bootstrap&& secret, std::uint64_t now_ms, Policy crypto = {} );
  ~SessionClient();
  SessionClient( const SessionClient& ) = delete;
  SessionClient& operator=( const SessionClient& ) = delete;
  Bytes retry( std::uint64_t now_ms );
  // The eventual terminal event loop must call tick even while idle.
  void tick( std::uint64_t now_ms );
  void stop() noexcept;
  void revalidate_path();
  ClientEvent receive( const UdpEndpoint& source, const Bytes& packet, std::uint64_t now_ms );
  Bytes send( const Bytes& payload, std::uint64_t now_ms );
  Bytes close( std::uint64_t now_ms );
  ClientState state() const noexcept;
  const UdpEndpoint& server() const noexcept;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace phantom
#endif
