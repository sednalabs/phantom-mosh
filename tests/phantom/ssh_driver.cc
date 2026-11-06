// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Test driver, not an installed launcher or terminal frontend.
#include "ssh_startup.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
void interrupt( int ) {}
int open_descriptors()
{
  DIR* directory = ::opendir( "/proc/self/fd" );
  if ( !directory )
    return -1;
  int count = 0;
  while ( const auto* entry = ::readdir( directory ) )
    if ( entry->d_name[0] != '.' )
      ++count;
  ::closedir( directory );
  return count;
}
}
int main( int argc, char** argv )
{
  if ( argc != 8 )
    return 2;
  phantom::SshStartupOptions options;
  options.ssh_path = argv[1];
  options.destination = argv[2];
  options.server_path = argv[3];
  options.config_path = argv[4];
  options.timeout = std::chrono::milliseconds( std::stoi( argv[5] ) );
  options.cancel_fd = std::stoi( argv[6] );
  const bool exchange = std::string( argv[7] ) == "udp";
  if ( std::getenv( "PHANTOM_TEST_IGNORE_SIGCHLD" ) )
    ::signal( SIGCHLD, SIG_IGN );
  if ( std::getenv( "PHANTOM_TEST_INTERRUPTS" ) ) {
    struct sigaction action
    {};
    action.sa_handler = interrupt;
    ::sigemptyset( &action.sa_mask );
    ::sigaction( SIGALRM, &action, nullptr );
    itimerval timer {};
    timer.it_interval.tv_usec = 2000;
    timer.it_value = timer.it_interval;
    ::setitimer( ITIMER_REAL, &timer, nullptr );
  }
  if ( std::getenv( "PHANTOM_TEST_CLOSED_STDIN" ) )
    ::close( STDIN_FILENO );
  const int descriptors_before = open_descriptors();
  int result = 0;
  try {
    auto offer = phantom::start_over_ssh( options );
    if ( exchange ) {
      phantom::Session session( phantom::Role::client, std::move( offer.secret ), 0 );
      struct Socket
      {
        int fd = ::socket( AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0 );
        ~Socket()
        {
          if ( fd >= 0 )
            ::close( fd );
        }
      } socket;
      sockaddr_in address {};
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
      address.sin_port = htons( offer.server_port );
      const phantom::Bytes payload { 1, 3, 3, 7 };
      const auto wire = session.seal( payload, 0 );
      if ( socket.fd < 0 || ::connect( socket.fd, reinterpret_cast<sockaddr*>( &address ), sizeof( address ) ) < 0
           || ::send( socket.fd, wire.data(), wire.size(), 0 ) != static_cast<ssize_t>( wire.size() ) )
        throw phantom::Error( "test UDP send failed" );
      pollfd event { socket.fd, POLLIN, 0 };
      if ( ::poll( &event, 1, 2000 ) != 1 )
        throw phantom::Error( "test UDP reply timed out" );
      phantom::Bytes reply( phantom::MAX_DATAGRAM + 1 );
      const auto size = ::recv( socket.fd, reply.data(), reply.size(), 0 );
      if ( size < 0 )
        throw phantom::Error( "test UDP read failed" );
      reply.resize( static_cast<std::size_t>( size ) );
      const auto opened = session.open( reply, 0 );
      if ( !opened || opened->payload != payload )
        throw phantom::Error( "test UDP authentication failed" );
    }
    std::cout << "accepted\n";
  } catch ( const std::exception& e ) {
    std::cerr << e.what() << '\n';
    result = 1;
  }
  // The supervisor must reap its child, but must not consume borrowed handles.
  if ( ::waitpid( -1, nullptr, WNOHANG ) != -1 || errno != ECHILD )
    return 3;
  if ( options.cancel_fd >= 0 && ::fcntl( options.cancel_fd, F_GETFD ) < 0 )
    return 4;
  if ( descriptors_before < 0 || open_descriptors() != descriptors_before )
    return 5;
  return result;
}
