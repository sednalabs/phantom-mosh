// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_STARTUP_H
#define PHANTOM_MOSH_STARTUP_H

#include "record.h"
#include <array>
#include <string_view>

namespace phantom {
constexpr std::string_view STARTUP_COMMAND = "PHANTOM CONNECT ";
constexpr std::string_view STARTUP_ROLES = " server client ";
constexpr std::size_t STARTUP_MAX_BYTES
  = STARTUP_COMMAND.size() + PROFILE_ID.size() + STARTUP_ROLES.size() + 5 + 1 + BootstrapText::size() + 1;

// Sensitive plaintext for an authenticated, confidential setup channel only.
// Views expire on move/destruction/clear. No implicit string or stream conversion.
class StartupFrame
{
public:
  ~StartupFrame();
  StartupFrame( StartupFrame&& other ) noexcept;
  StartupFrame& operator=( StartupFrame&& other ) noexcept;
  StartupFrame( const StartupFrame& ) = delete;
  StartupFrame& operator=( const StartupFrame& ) = delete;
  std::string_view view() const noexcept { return { data_.data(), size_ }; }
  void clear() noexcept;

private:
  StartupFrame() = default;
  std::array<char, STARTUP_MAX_BYTES> data_ {};
  std::size_t size_ = 0;
  friend StartupFrame make_startup_offer( std::uint16_t server_port, const Bootstrap& secret );
};

StartupFrame make_startup_offer( std::uint16_t server_port, const Bootstrap& secret );

// The port belongs to the SSH-authenticated server. This message cannot select
// a different host or grant authentication by itself.
struct StartupOffer
{
  std::uint16_t server_port;
  Bootstrap secret;
};

// One finite, dedicated stream. feed() accepts arbitrary read boundaries;
// finish() is called only after EOF. Any failure permanently closes the decoder.
// The caller owns authentication, a total deadline, and erasure of input copies.
class StartupDecoder
{
public:
  StartupDecoder() = default;
  ~StartupDecoder();
  StartupDecoder( const StartupDecoder& ) = delete;
  StartupDecoder& operator=( const StartupDecoder& ) = delete;
  StartupDecoder( StartupDecoder&& ) = delete;
  StartupDecoder& operator=( StartupDecoder&& ) = delete;
  void feed( std::string_view chunk );
  StartupOffer finish();

private:
  std::array<char, STARTUP_MAX_BYTES> data_ {};
  std::size_t size_ = 0;
  bool closed_ = false;
  void clear() noexcept;
  [[noreturn]] void reject();
};
} // namespace phantom
#endif
