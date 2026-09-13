// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "session_offer.h"
#include <algorithm>
#include <charconv>
#include <openssl/crypto.h>

namespace phantom {
namespace {
constexpr std::string_view PREFIX = "PHANTOM SESSION ";
constexpr std::string_view ROLES = " server client ";
}
void SessionFrame::clear() noexcept
{
  OPENSSL_cleanse( bytes_.data(), bytes_.size() );
  size_ = 0;
}
SessionFrame::~SessionFrame()
{
  clear();
}
SessionFrame::SessionFrame( SessionFrame&& other ) noexcept : bytes_( other.bytes_ ), size_( other.size_ )
{
  other.clear();
}
SessionFrame& SessionFrame::operator=( SessionFrame&& other ) noexcept
{
  if ( this != &other ) {
    clear();
    bytes_ = other.bytes_;
    size_ = other.size_;
    other.clear();
  }
  return *this;
}
SessionFrame make_session_offer( const UdpEndpoint& endpoint, const Bootstrap& secret )
{
  SessionFrame frame;
  const auto host = endpoint.host();
  const auto key = secret.encode();
  char port[5];
  auto number = std::to_chars( port, port + sizeof( port ), endpoint.port() );
  if ( number.ec != std::errc {} )
    throw Error( "invalid session port" );
  for ( auto part : { PREFIX,
                      SESSION_PROFILE,
                      ROLES,
                      std::string_view( host ),
                      std::string_view( " " ),
                      std::string_view( port, static_cast<std::size_t>( number.ptr - port ) ) } ) {
    if ( part.size() > frame.bytes_.size() - frame.size_ )
      throw Error( "session offer exceeds budget" );
    std::copy( part.begin(), part.end(), frame.bytes_.begin() + static_cast<std::ptrdiff_t>( frame.size_ ) );
    frame.size_ += part.size();
  }
  if ( frame.bytes_.size() - frame.size_ < key.size() + 2 )
    throw Error( "session offer exceeds budget" );
  frame.bytes_[frame.size_++] = ' ';
  std::copy_n( key.data(), key.size(), frame.bytes_.data() + frame.size_ );
  frame.size_ += key.size();
  frame.bytes_[frame.size_++] = '\n';
  return frame;
}
void SessionOfferDecoder::clear() noexcept
{
  OPENSSL_cleanse( bytes_.data(), bytes_.size() );
  size_ = 0;
  closed_ = true;
}
SessionOfferDecoder::~SessionOfferDecoder()
{
  clear();
}
[[noreturn]] void SessionOfferDecoder::reject()
{
  clear();
  throw Error( "invalid session offer" );
}
void SessionOfferDecoder::feed( std::string_view chunk )
{
  if ( closed_ || chunk.size() > bytes_.size() - size_ )
    reject();
  for ( char c : chunk ) {
    if ( ( size_ && bytes_[size_ - 1] == '\n' ) || ( c != '\n' && ( c < ' ' || c > '~' ) ) )
      reject();
    bytes_[size_++] = c;
  }
}
SessionOffer SessionOfferDecoder::finish()
{
  if ( closed_ || !size_ || bytes_[size_ - 1] != '\n' )
    reject();
  try {
    std::string_view input( bytes_.data(), size_ - 1 );
    for ( auto field : { PREFIX, SESSION_PROFILE, ROLES } ) {
      if ( input.substr( 0, field.size() ) != field )
        reject();
      input.remove_prefix( field.size() );
    }
    const auto end_host = input.find( ' ' );
    if ( end_host == std::string_view::npos )
      reject();
    const auto host = input.substr( 0, end_host );
    input.remove_prefix( end_host + 1 );
    const auto end_port = input.find( ' ' );
    if ( end_port == std::string_view::npos || !end_port || end_port > 5 || input[0] == '0' )
      reject();
    const auto port_text = input.substr( 0, end_port );
    for ( char c : port_text )
      if ( c < '0' || c > '9' )
        reject();
    std::uint16_t port = 0;
    const auto parsed = std::from_chars( port_text.data(), port_text.data() + port_text.size(), port );
    if ( parsed.ec != std::errc {} || parsed.ptr != port_text.data() + port_text.size() )
      reject();
    auto endpoint = UdpEndpoint::parse( host, port );
    if ( endpoint.host() != host )
      reject(); // canonical representation only
    input.remove_prefix( end_port + 1 );
    SessionOffer offer { endpoint, Bootstrap::parse( input ) };
    clear();
    return offer;
  } catch ( const Error& ) {
    reject();
  } catch ( ... ) {
    clear();
    throw;
  }
}
} // namespace phantom
