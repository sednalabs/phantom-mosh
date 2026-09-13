// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "startup_posix.h"
#include <cerrno>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

namespace phantom {
namespace {
struct OwnedDescriptor
{
  const int fd;
  explicit OwnedDescriptor( int value ) : fd( value ) {}
  OwnedDescriptor( const OwnedDescriptor& ) = delete;
  OwnedDescriptor& operator=( const OwnedDescriptor& ) = delete;
  ~OwnedDescriptor()
  {
    // Do not retry close after EINTR: on supported Linux/macOS platforms the
    // descriptor may already be closed and reused by another thread.
    if ( fd >= 0 )
      ::close( fd );
  }
};
struct ReadBuffer
{
  std::array<char, STARTUP_MAX_BYTES + 1> data {};
  ~ReadBuffer() { OPENSSL_cleanse( data.data(), data.size() ); }
};
[[noreturn]] void io_error()
{
  throw Error( "startup channel failed" );
}
} // namespace
StartupOffer read_startup_offer_fd( int fd, std::chrono::milliseconds timeout )
{
  OwnedDescriptor owned( fd );
  if ( fd < 0 || timeout.count() < 1 || timeout.count() > 120000 )
    throw Error( "invalid startup channel parameters" );
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  struct stat info {};
  if ( ::fstat( fd, &info ) < 0 )
    io_error();
  if ( !S_ISFIFO( info.st_mode ) ) {
    int kind = 0;
    socklen_t size = sizeof( kind );
    if ( !S_ISSOCK( info.st_mode ) || ::getsockopt( fd, SOL_SOCKET, SO_TYPE, &kind, &size ) < 0
         || kind != SOCK_STREAM )
      io_error();
  }
  const int status_flags = ::fcntl( fd, F_GETFL );
  const int descriptor_flags = ::fcntl( fd, F_GETFD );
  if ( status_flags < 0 || descriptor_flags < 0
       || ::fcntl( fd, F_SETFL, status_flags | O_NONBLOCK ) < 0
       || ::fcntl( fd, F_SETFD, descriptor_flags | FD_CLOEXEC ) < 0 )
    io_error();
  StartupDecoder decoder;
  ReadBuffer buffer;
  for ( ;; ) {
    const auto now = std::chrono::steady_clock::now();
    if ( now >= deadline )
      throw Error( "startup channel timed out" );
    const auto remaining = std::chrono::ceil<std::chrono::milliseconds>( deadline - now );
    pollfd event { fd, POLLIN, 0 };
    const int ready = ::poll( &event, 1, static_cast<int>( remaining.count() ) );
    if ( ready < 0 ) {
      if ( errno == EINTR )
        continue;
      io_error();
    }
    if ( ready == 0 )
      continue;
    if ( std::chrono::steady_clock::now() >= deadline )
      throw Error( "startup channel timed out" );
    if ( event.revents & POLLNVAL )
      io_error();
    if ( !( event.revents & ( POLLIN | POLLHUP ) ) )
      io_error();
    const auto count = ::read( fd, buffer.data.data(), buffer.data.size() );
    if ( count < 0 ) {
      if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK )
        continue;
      io_error();
    }
    if ( count == 0 )
      return decoder.finish();
    decoder.feed( { buffer.data.data(), static_cast<std::size_t>( count ) } );
    OPENSSL_cleanse( buffer.data.data(), buffer.data.size() );
  }
}
} // namespace phantom
