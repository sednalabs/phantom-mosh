// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Real loopback UDP admission test, not an SSH/PTY/SSP test.
#include "record.h"
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>
#include <utility>
using namespace phantom;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
struct Socket {
  int fd = -1; sockaddr_in address{};
  Socket() {
    fd = ::socket(AF_INET, SOCK_DGRAM, 0); CHECK(fd >= 0);
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) { ::close(fd); throw std::runtime_error("bind"); }
    socklen_t size = sizeof(address);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) { ::close(fd); throw std::runtime_error("getsockname"); }
  }
  ~Socket() { if (fd >= 0) ::close(fd); }
  Socket(const Socket&) = delete; Socket& operator=(const Socket&) = delete;
  void send(const Socket& destination, const Bytes& data) {
    CHECK(::sendto(fd, data.data(), data.size(), 0, reinterpret_cast<const sockaddr*>(&destination.address), sizeof(destination.address)) == static_cast<ssize_t>(data.size()));
  }
  std::pair<Bytes, sockaddr_in> receive() {
    pollfd p{fd, POLLIN, 0}; CHECK(::poll(&p, 1, 2000) == 1 && (p.revents & POLLIN));
    Bytes data(MAX_DATAGRAM + 1); sockaddr_in peer{}; socklen_t size = sizeof(peer);
    const auto n = ::recvfrom(fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&peer), &size);
    CHECK(n >= 0); data.resize(static_cast<std::size_t>(n)); return {std::move(data), peer};
  }
};
int main() {
  try {
    constexpr auto key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    Session client(Role::client, Bootstrap::parse(key), 0), server(Role::server, Bootstrap::parse(key), 0);
    Socket first, roaming, attacker, target; sockaddr_in admitted{};
    auto ingest = [&] { auto packet = target.receive(); auto opened = server.open(packet.first, 0);
      if (opened && opened->newest) admitted = packet.second; return opened; };
    const auto first_packet = client.seal({1}, 0), delayed = client.seal({2}, 0);
    first.send(target, first_packet); CHECK(ingest()); CHECK(admitted.sin_port == first.address.sin_port);
    auto corrupt = first_packet; corrupt.back() ^= 1;
    attacker.send(target, corrupt); CHECK(!ingest()); CHECK(admitted.sin_port == first.address.sin_port);
    roaming.send(target, client.seal({3}, 0)); CHECK(ingest()); CHECK(admitted.sin_port == roaming.address.sin_port);
    first.send(target, delayed); auto old = ingest(); CHECK(old && !old->newest); CHECK(admitted.sin_port == roaming.address.sin_port);
    attacker.send(target, first_packet); CHECK(!ingest()); CHECK(admitted.sin_port == roaming.address.sin_port);
    target.send(roaming, server.seal({4}, 0)); auto reply = roaming.receive();
    auto opened = client.open(reply.first, 0); CHECK(opened && opened->payload == Bytes{4});
    std::cout << "PASS real UDP rebind, forged rebind, delayed old path and replay\n"; return 0;
  } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
