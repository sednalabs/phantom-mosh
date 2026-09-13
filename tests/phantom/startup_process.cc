// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Test child: receives its bootstrap only through an inherited descriptor,
// then exchanges actual UDP records with the independent Python test peer.
#include "startup_posix.h"
#include <arpa/inet.h>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <utility>

using namespace phantom;
namespace {
volatile std::sig_atomic_t interruptions = 0;
void interrupt( int )
{
  ++interruptions;
}
int number( std::string_view text )
{
  int value = -1;
  const auto parsed = std::from_chars( text.data(), text.data() + text.size(), value );
  if ( parsed.ec != std::errc {} || parsed.ptr != text.data() + text.size() )
    throw Error( "invalid test arguments" );
  return value;
}
void require_closed( int fd )
{
  errno = 0;
  if ( ::fcntl( fd, F_GETFD ) != -1 || errno != EBADF )
    throw Error( "startup descriptor leaked" );
}
struct Socket
{
  const int fd = ::socket( AF_INET, SOCK_DGRAM, 0 );
  ~Socket()
  {
    if ( fd >= 0 )
      ::close( fd );
  }
};
} // namespace
int main( int argc, char** argv )
{
  if ( argc != 3 && argc != 4 )
    return 2;
  int fd = -1;
  try {
    fd = number( argv[1] );
    const auto timeout = std::chrono::milliseconds( number( argv[2] ) );
    if ( argc == 4 ) {
      struct sigaction action {};
      action.sa_handler = interrupt;
      ::sigemptyset( &action.sa_mask );
      itimerval timer {};
      timer.it_interval.tv_usec = timer.it_value.tv_usec = 10000;
      if ( ::sigaction( SIGALRM, &action, nullptr ) < 0 || ::setitimer( ITIMER_REAL, &timer, nullptr ) < 0 )
        return 2;
    }
    auto offer = read_startup_offer_fd( fd, timeout );
    require_closed( fd );
    Session session( Role::client, std::move( offer.secret ), 0 );
    const std::string message = "startup handoff";
    const auto record = session.seal( Bytes( message.begin(), message.end() ), 0 );
    Socket socket;
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
    address.sin_port = htons( offer.server_port );
    if ( socket.fd < 0
         || ::connect( socket.fd, reinterpret_cast<sockaddr*>( &address ), sizeof( address ) ) < 0
         || ::send( socket.fd, record.data(), record.size(), 0 ) != static_cast<ssize_t>( record.size() ) )
      throw Error( "test UDP send failed" );
    pollfd event { socket.fd, POLLIN, 0 };
    if ( ::poll( &event, 1, 2000 ) != 1 || !( event.revents & POLLIN ) )
      throw Error( "test UDP reply missing" );
    Bytes buffer( MAX_DATAGRAM + 1 );
    const auto n = ::recv( socket.fd, buffer.data(), buffer.size(), 0 );
    if ( n < 0 )
      throw Error( "test UDP receive failed" );
    buffer.resize( static_cast<std::size_t>( n ) );
    auto opened = session.open( buffer, 0 );
    const std::string reply = "handoff confirmed";
    if ( !opened || opened->payload != Bytes( reply.begin(), reply.end() ) )
      throw Error( "test UDP authentication failed" );
    std::cout << "handoff confirmed\n";
    return 0;
  } catch ( const std::exception& ) {
    try {
      require_closed( fd );
    } catch ( const std::exception& ) {
      return 2;
    }
    if ( argc == 4 && interruptions == 0 )
      return 2;
    // Test the same redacted reporting discipline expected of the launcher.
    std::cerr << "startup rejected\n";
    return 1;
  }
}
