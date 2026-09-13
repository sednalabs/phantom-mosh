// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "session_udp.h"
#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <utility>
namespace phantom {
namespace {
struct Address
{
  sockaddr_storage storage {};
  socklen_t size;
};
Address address( const UdpEndpoint& endpoint, bool ephemeral = false )
{
  Address out;
  if ( endpoint.ipv6() ) {
    auto* a = reinterpret_cast<sockaddr_in6*>( &out.storage );
    a->sin6_family = AF_INET6;
    a->sin6_port = ephemeral ? 0 : htons( endpoint.port() );
    if ( inet_pton( AF_INET6, endpoint.host().c_str(), &a->sin6_addr ) != 1 )
      throw Error( "UDP address conversion failed" );
    out.size = sizeof( *a );
  } else {
    auto* a = reinterpret_cast<sockaddr_in*>( &out.storage );
    a->sin_family = AF_INET;
    a->sin_port = ephemeral ? 0 : htons( endpoint.port() );
    if ( inet_pton( AF_INET, endpoint.host().c_str(), &a->sin_addr ) != 1 )
      throw Error( "UDP address conversion failed" );
    out.size = sizeof( *a );
  }
  return out;
}
UdpEndpoint endpoint( const sockaddr_storage& storage, socklen_t size )
{
  std::array<char, INET6_ADDRSTRLEN> host {};
  std::uint16_t port = 0;
  if ( storage.ss_family == AF_INET && size >= sizeof( sockaddr_in ) ) {
    const auto* a = reinterpret_cast<const sockaddr_in*>( &storage );
    if ( !inet_ntop( AF_INET, &a->sin_addr, host.data(), host.size() ) )
      throw Error( "UDP address conversion failed" );
    port = ntohs( a->sin_port );
  } else if ( storage.ss_family == AF_INET6 && size >= sizeof( sockaddr_in6 ) ) {
    const auto* a = reinterpret_cast<const sockaddr_in6*>( &storage );
    if ( a->sin6_scope_id != 0 || !inet_ntop( AF_INET6, &a->sin6_addr, host.data(), host.size() ) )
      throw Error( "unsupported UDP address scope" );
    port = ntohs( a->sin6_port );
  } else
    throw Error( "invalid UDP socket address" );
  return UdpEndpoint::parse( host.data(), port );
}
}
SessionSocket SessionSocket::bind( std::string_view host, std::uint16_t port )
{
  const auto requested = UdpEndpoint::parse( host, port ? port : 1 );
  const auto a = address( requested, !port );
  const int fd = ::socket( requested.ipv6() ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0 );
  if ( fd < 0 )
    throw Error( "UDP socket creation failed" );
  try {
    const int one = 1;
    if ( requested.ipv6() && ::setsockopt( fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof( one ) ) != 0 )
      throw Error( "UDP socket configuration failed" );
    if ( ::bind( fd, reinterpret_cast<const sockaddr*>( &a.storage ), a.size ) != 0 )
      throw Error( "UDP bind failed" );
    sockaddr_storage local {};
    socklen_t size = sizeof( local );
    if ( ::getsockname( fd, reinterpret_cast<sockaddr*>( &local ), &size ) != 0 )
      throw Error( "UDP address query failed" );
    return SessionSocket( fd, endpoint( local, size ) );
  } catch ( ... ) {
    ::close( fd );
    throw;
  }
}
SessionSocket SessionSocket::client_to( const UdpEndpoint& peer )
{
  const auto a = address( peer );
  const int fd = ::socket( peer.ipv6() ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0 );
  if ( fd < 0 )
    throw Error( "UDP socket creation failed" );
  try {
    if ( ::connect( fd, reinterpret_cast<const sockaddr*>( &a.storage ), a.size ) != 0 )
      throw Error( "UDP peer route is unavailable" );
    sockaddr_storage local {};
    socklen_t size = sizeof( local );
    if ( ::getsockname( fd, reinterpret_cast<sockaddr*>( &local ), &size ) != 0 )
      throw Error( "UDP local route query failed" );
    return SessionSocket( fd, endpoint( local, size ) );
  } catch ( ... ) {
    ::close( fd );
    throw;
  }
}
SessionSocket::~SessionSocket()
{
  if ( fd_ >= 0 )
    ::close( fd_ );
}
SessionSocket::SessionSocket( SessionSocket&& other ) noexcept : fd_( other.fd_ ), local_( other.local_ )
{
  other.fd_ = -1;
}
bool SessionSocket::send( const UdpEndpoint& peer, const Bytes& bytes )
{
  if ( bytes.size() > MAX_DATAGRAM || peer.ipv6() != local_.ipv6() )
    throw Error( "invalid UDP send" );
  const auto a = address( peer );
  const auto sent = ::sendto(
    fd_, bytes.data(), bytes.size(), MSG_DONTWAIT, reinterpret_cast<const sockaddr*>( &a.storage ), a.size );
  if ( sent < 0 ) {
    if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS || errno == ENETUNREACH
         || errno == EHOSTUNREACH || errno == ECONNREFUSED || errno == EMSGSIZE )
      return false;
    throw Error( "UDP send failed" );
  }
  return static_cast<std::size_t>( sent ) == bytes.size();
}
SocketRead SessionSocket::receive_one()
{
  std::array<unsigned char, MAX_DATAGRAM> buffer {};
  sockaddr_storage peer {};
  iovec io { buffer.data(), buffer.size() };
  msghdr message {};
  message.msg_name = &peer;
  message.msg_namelen = sizeof( peer );
  message.msg_iov = &io;
  message.msg_iovlen = 1;
  const auto size = ::recvmsg( fd_, &message, MSG_DONTWAIT );
  if ( size < 0 ) {
    if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED )
      return { false, {} };
    throw Error( "UDP receive failed" );
  }
  if ( message.msg_flags & ( MSG_TRUNC | MSG_CTRUNC ) || static_cast<std::size_t>( size ) > buffer.size() )
    return { true, {} };
  try {
    return {
      true,
      InboundDatagram { endpoint( peer, message.msg_namelen ), Bytes( buffer.begin(), buffer.begin() + size ) } };
  } catch ( const Error& ) {
    return { true, {} };
  }
}
std::optional<InboundDatagram> SessionSocket::receive()
{
  return receive_one().datagram;
}
void SessionSocket::wait( int timeout_ms )
{
  if ( timeout_ms < 0 || timeout_ms > 1000 )
    throw Error( "invalid UDP wait budget" );
  pollfd event { fd_, POLLIN, 0 };
  const int result = ::poll( &event, 1, timeout_ms );
  if ( ( result < 0 && errno != EINTR ) || ( event.revents & POLLNVAL ) )
    throw Error( "UDP wait failed" );
}
std::uint64_t session_time_ms()
{
  timespec time {};
  if ( ::clock_gettime( CLOCK_BOOTTIME, &time ) != 0 || time.tv_sec < 0 )
    throw Error( "session clock failed" );
  return static_cast<std::uint64_t>( time.tv_sec ) * 1000 + static_cast<std::uint64_t>( time.tv_nsec ) / 1000000;
}
} // namespace phantom
