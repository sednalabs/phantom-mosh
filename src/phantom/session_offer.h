// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_SESSION_OFFER_H
#define PHANTOM_MOSH_SESSION_OFFER_H
#include "remote_session.h"

namespace phantom {
constexpr std::size_t SESSION_OFFER_MAX = 160;
struct SessionOffer
{
  UdpEndpoint server;
  Bootstrap secret;
};
class SessionFrame
{
public:
  SessionFrame() = default;
  ~SessionFrame();
  SessionFrame( SessionFrame&& other ) noexcept;
  SessionFrame& operator=( SessionFrame&& other ) noexcept;
  SessionFrame( const SessionFrame& ) = delete;
  SessionFrame& operator=( const SessionFrame& ) = delete;
  std::string_view view() const noexcept { return { bytes_.data(), size_ }; }
  void clear() noexcept;
private:
  std::array<char, SESSION_OFFER_MAX> bytes_ {};
  std::size_t size_ = 0;
  friend SessionFrame make_session_offer( const UdpEndpoint&, const Bootstrap& );
};
SessionFrame make_session_offer( const UdpEndpoint& endpoint, const Bootstrap& secret );
// Exactly one canonical numeric endpoint, role pair and secret over a dedicated
// authenticated stream. No banner scanning, DNS, fallback or partial admission.
class SessionOfferDecoder
{
public:
  SessionOfferDecoder() = default;
  ~SessionOfferDecoder();
  SessionOfferDecoder( const SessionOfferDecoder& ) = delete;
  SessionOfferDecoder& operator=( const SessionOfferDecoder& ) = delete;
  void feed( std::string_view chunk );
  SessionOffer finish();
private:
  std::array<char, SESSION_OFFER_MAX> bytes_ {};
  std::size_t size_ = 0;
  bool closed_ = false;
  void clear() noexcept;
  [[noreturn]] void reject();
};
} // namespace phantom
#endif
