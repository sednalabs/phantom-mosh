// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Copyright 2026 Phantom Mosh contributors
#ifndef PHANTOM_MOSH_RECORD_H
#define PHANTOM_MOSH_RECORD_H
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>
namespace phantom {
using Bytes = std::vector<unsigned char>;
constexpr std::string_view PROFILE_ID = "phantom-mosh/v3/draft-01";
constexpr std::size_t RECORD_OVERHEAD = 32;
constexpr std::size_t MAX_DATAGRAM = 1200;
constexpr std::size_t MAX_PAYLOAD = MAX_DATAGRAM - RECORD_OVERHEAD;
constexpr std::size_t REPLAY_WINDOW = 4096;
constexpr std::uint64_t MAX_PACKET_NUMBER = ( std::uint64_t { 1 } << 63 ) - 1;
class Error : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};
// Move-only secret-bearing text. Callers must erase their own input/output copies.
class BootstrapText
{
public:
  BootstrapText() = default;
  ~BootstrapText();
  BootstrapText( BootstrapText&& other ) noexcept;
  BootstrapText& operator=( BootstrapText&& other ) noexcept;
  BootstrapText( const BootstrapText& ) = delete;
  BootstrapText& operator=( const BootstrapText& ) = delete;
  const char* data() const noexcept { return text_.data(); }
  static constexpr std::size_t size() noexcept { return 43; }

private:
  std::array<char, 44> text_ {};
  friend class Bootstrap;
};
class Bootstrap
{
public:
  static Bootstrap random();
  static Bootstrap parse( std::string_view canonical_base64 );
  BootstrapText encode() const;
  ~Bootstrap();
  Bootstrap( Bootstrap&& other ) noexcept;
  Bootstrap& operator=( Bootstrap&& other ) noexcept;
  Bootstrap( const Bootstrap& ) = delete;
  Bootstrap& operator=( const Bootstrap& ) = delete;
  bool valid() const noexcept { return valid_; }

private:
  Bootstrap() = default;
  void clear() noexcept;
  std::array<unsigned char, 32> secret_ {};
  bool valid_ = false;
  friend class Session;
};
enum class Role
{
  client,
  server
};
// Local resource bounds, not unauthenticated wire negotiation.
struct Policy
{
  std::uint64_t rekey_packets = std::uint64_t { 1 } << 20;
  std::uint64_t hard_packets = std::uint64_t { 1 } << 24;
  std::uint64_t rekey_ms = 60 * 60 * 1000;
  std::uint64_t previous_key_ms = 30 * 1000;
  std::uint64_t failed_verifications = std::uint64_t { 1 } << 32;
};
struct Received
{
  std::uint64_t packet_number;
  std::uint32_t epoch;
  bool newest; // Only an authenticated newest record may authorize rebinding.
  Bytes payload;
};
// Evaluator-only diagnostics; these must not enter a passive classifier.
struct StateView
{
  std::uint32_t send_epoch;
  std::uint32_t receive_epoch;
  std::uint32_t peer_ack;
  std::uint64_t sent_in_epoch;
  std::uint64_t failed_verifications;
  unsigned int last_open_attempts;
  bool previous_key_retained;
  bool closed;
};
class Session
{
public:
  // Consumes the bootstrap even on failure. An external authenticated channel
  // must already bind both roles and the exact draft/suite selection.
  Session( Role role, Bootstrap&& bootstrap, std::uint64_t now_ms, Policy policy = {} );
  ~Session();
  Session( const Session& ) = delete;
  Session& operator=( const Session& ) = delete;
  Session( Session&& ) = delete;
  Session& operator=( Session&& ) = delete;
  // Single-owner, non-thread-safe API. A packet number is consumed before crypto
  // starts. Never rewind after a provider or sendto failure.
  Bytes seal( const Bytes& payload, std::uint64_t now_ms );
  // No epoch/ACK/replay/address state commits before authentication/validation.
  std::optional<Received> open( const Bytes& datagram, std::uint64_t now_ms );
  // The owner must tick while idle to retire previous receive keys.
  void tick( std::uint64_t now_ms );
  void close() noexcept;
  StateView state() const noexcept;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace phantom
#endif
