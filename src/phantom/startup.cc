// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "startup.h"
#include <algorithm>
#include <charconv>
#include <openssl/crypto.h>
#include <utility>

namespace phantom {
StartupFrame::~StartupFrame()
{
  clear();
}
StartupFrame::StartupFrame( StartupFrame&& other ) noexcept : data_( other.data_ ), size_( other.size_ )
{
  other.clear();
}
StartupFrame& StartupFrame::operator=( StartupFrame&& other ) noexcept
{
  if ( this != &other ) {
    clear();
    data_ = other.data_;
    size_ = other.size_;
    other.clear();
  }
  return *this;
}
void StartupFrame::clear() noexcept
{
  OPENSSL_cleanse( data_.data(), data_.size() );
  size_ = 0;
}
StartupFrame make_startup_offer( std::uint16_t server_port, const Bootstrap& secret )
{
  if ( server_port == 0 )
    throw Error( "invalid startup port" );
  const auto encoded = secret.encode();
  StartupFrame frame;
  char* next = frame.data_.data();
  for ( auto field : { STARTUP_COMMAND, PROFILE_ID, STARTUP_ROLES } )
    next = std::copy( field.begin(), field.end(), next );
  const auto port = std::to_chars( next, next + 5, server_port );
  if ( port.ec != std::errc {} )
    throw Error( "invalid startup port" );
  next = port.ptr;
  *next++ = ' ';
  next = std::copy_n( encoded.data(), encoded.size(), next );
  *next++ = '\n';
  frame.size_ = static_cast<std::size_t>( next - frame.data_.data() );
  return frame;
}
StartupDecoder::~StartupDecoder()
{
  clear();
}
void StartupDecoder::clear() noexcept
{
  OPENSSL_cleanse( data_.data(), data_.size() );
  size_ = 0;
  closed_ = true;
}
[[noreturn]] void StartupDecoder::reject()
{
  clear();
  // Deliberately exclude input fragments, including on profile/port failures.
  throw Error( "invalid startup message" );
}
void StartupDecoder::feed( std::string_view chunk )
{
  if ( closed_ || chunk.size() > data_.size() - size_ )
    reject();
  for ( const char c : chunk ) {
    if ( ( size_ && data_[size_ - 1] == '\n' ) || ( c != '\n' && ( c < ' ' || c > '~' ) ) )
      reject();
    data_[size_++] = c;
  }
}
StartupOffer StartupDecoder::finish()
{
  if ( closed_ || !size_ || data_[size_ - 1] != '\n' )
    reject();
  try {
    std::string_view input( data_.data(), size_ - 1 );
    for ( auto field : { STARTUP_COMMAND, PROFILE_ID, STARTUP_ROLES } ) {
      if ( input.substr( 0, field.size() ) != field )
        reject();
      input.remove_prefix( field.size() );
    }
    const auto separator = input.find( ' ' );
    if ( separator == std::string_view::npos || separator == 0 || separator > 5 || input[0] == '0' )
      reject();
    const auto port_text = input.substr( 0, separator );
    for ( char c : port_text )
      if ( c < '0' || c > '9' )
        reject();
    std::uint16_t port = 0;
    const auto parsed = std::from_chars( port_text.data(), port_text.data() + port_text.size(), port );
    if ( parsed.ec != std::errc {} || parsed.ptr != port_text.data() + port_text.size() || port == 0 )
      reject();
    input.remove_prefix( separator + 1 );
    StartupOffer offer { port, Bootstrap::parse( input ) };
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
