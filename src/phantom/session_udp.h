// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#ifndef PHANTOM_MOSH_SESSION_UDP_H
#define PHANTOM_MOSH_SESSION_UDP_H
#include "remote_session.h"
namespace phantom {
struct InboundDatagram { UdpEndpoint peer; Bytes bytes; };
// Distinguish a discarded datagram from an empty socket for receive-work budgets.
struct SocketRead { bool consumed; std::optional<InboundDatagram> datagram; };
// Linux socket owner. Port zero requests a fresh ephemeral port; host remains
// an explicit numeric unicast address. No shared socket or descriptor cloning.
class SessionSocket
{
public:
  static SessionSocket bind( std::string_view host, std::uint16_t port = 0 );
  // Use the OS route to a numeric authenticated peer. UDP connect does not
  // establish or authenticate a session; SessionClient still proves the path.
  static SessionSocket client_to( const UdpEndpoint& peer );
  ~SessionSocket();
  SessionSocket( SessionSocket&& other ) noexcept;
  SessionSocket& operator=( SessionSocket&& ) = delete;
  SessionSocket( const SessionSocket& ) = delete;
  SessionSocket& operator=( const SessionSocket& ) = delete;
  const UdpEndpoint& local() const noexcept { return local_; }
  bool send( const UdpEndpoint& peer, const Bytes& bytes );
  SocketRead receive_one();
  std::optional<InboundDatagram> receive();
  int fd() const noexcept { return fd_; }
  void wait( int timeout_ms );
private:
  SessionSocket( int fd, UdpEndpoint local ) : fd_( fd ), local_( local ) {}
  int fd_;
  const UdpEndpoint local_;
};
// CLOCK_BOOTTIME includes Linux suspension, unlike a steady_clock on some OSes.
std::uint64_t session_time_ms();
} // namespace phantom
#endif
