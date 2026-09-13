// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "remote_session.h"
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <utility>
using namespace phantom;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string(__func__) + ":" + std::to_string(__LINE__) + ": " #x); } while(false)
namespace {
constexpr auto KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
Bootstrap key() { return Bootstrap::parse(KEY); }
UdpEndpoint endpoint(unsigned int port = 60000) { return UdpEndpoint::parse("127.0.0.1", static_cast<std::uint16_t>(port)); }
RemotePolicy policy() { RemotePolicy p; p.startup_ms = 1000; p.path_ms = 100; p.drain_ms = 50; return p; }
template<class F> void rejects(F f) { try { f(); } catch(const Error&) { return; } throw std::runtime_error("expected rejection"); }
void handshake(RemoteSession& server, SessionClient& client, UdpEndpoint from, std::uint64_t now) {
  auto first = client.retry(now);
  auto challenge = server.receive(from, first, now);
  CHECK(challenge.reply && challenge.reply->peer == from && challenge.reply->datagram.size() <= first.size());
  auto confirm = client.receive(client.server(), challenge.reply->datagram, now);
  CHECK(confirm.reply);
  auto ready = server.receive(from, *confirm.reply, now);
  CHECK(ready.reply);
  client.receive(client.server(), ready.reply->datagram, now);
  CHECK(client.state() == ClientState::active && server.state() == RemoteState::active);
}
void addresses() {
  static_assert(!std::is_default_constructible_v<UdpEndpoint>);
  CHECK(UdpEndpoint::parse("2001:db8::1", 20) == UdpEndpoint::parse("2001:0db8:0:0:0:0:0:1", 20));
  CHECK(UdpEndpoint::parse("2001:db8::1", 20).host() == "2001:db8::1");
  for(auto host : {"", "alias", "0.0.0.0", "224.0.0.1", "255.255.255.255", "127.1", "::", "ff02::1", "fe80::1", "fe80::1%eth0", "::ffff:127.0.0.1"})
    rejects([&]{UdpEndpoint::parse(host, 20);});
  rejects([]{UdpEndpoint::parse(std::string("127.0.0.1\0extra",15),20);});
  rejects([]{UdpEndpoint::parse("127.0.0.1",0);});
}
void startup_cannot_be_renewed() {
  auto p = policy(); RemoteSession server(key(), 0, p); SessionClient client(endpoint(), key(), 0);
  CHECK(server.wait_ms(0) == 1000);
  for(std::uint64_t now = 0; now < 1000; now += 10) {
    CHECK(!server.receive(endpoint(), Bytes(49, 0x55), now).reply);
    auto r = server.receive(endpoint(), client.retry(now), now);
    CHECK(r.reply && !server.peer());
  }
  CHECK(server.state() == RemoteState::pending);
  CHECK(!server.receive(endpoint(), client.retry(1000), 1000).reply);
  CHECK(server.state() == RemoteState::closed && server.wait_ms(1000) == 0);
  server.stop(); server.stop();
}
void data_and_reorder() {
  RemoteSession server(key(),0,policy()); SessionClient client(endpoint(),key(),0); auto from = endpoint(40000);
  rejects([&]{client.send({},0);}); rejects([&]{server.send({},0);}); handshake(server,client,from,0);
  auto early = client.send({1,2},1), later = client.send({3,4},2);
  auto b = server.receive(from,later,2); auto a = server.receive(from,early,2);
  CHECK(b.data == std::optional<Bytes>(Bytes{3,4}) && a.data == std::optional<Bytes>(Bytes{1,2}));
  CHECK(!server.receive(from,early,2).data);
  Bytes payload(SESSION_MAX_DATA,0x51); auto out = server.send(payload,3);
  CHECK(out.peer == from && out.datagram.size() == MAX_DATAGRAM);
  CHECK(client.receive(endpoint(),out.datagram,3).data == std::optional<Bytes>(payload));
  rejects([&]{server.send(Bytes(SESSION_MAX_DATA+1),3);}); CHECK(server.state()==RemoteState::active);
  rejects([&]{client.send(Bytes(SESSION_MAX_DATA+1),3);}); CHECK(client.state()==ClientState::active);
}
void forged_path_and_lost_ready() {
  RemoteSession server(key(),0,policy()); SessionClient client(endpoint(),key(),0); auto from = endpoint(40000), attacker = endpoint(40001);
  auto challenge = server.receive(from,client.retry(0),0); CHECK(challenge.reply);
  // The client must not even consume the record from the wrong server address.
  CHECK(!client.receive(attacker,challenge.reply->datagram,0).reply);
  auto confirm = client.receive(endpoint(),challenge.reply->datagram,0); CHECK(confirm.reply);
  CHECK(!server.receive(attacker,*confirm.reply,0).reply); CHECK(!server.peer());
  // The same authenticated record was consumed from the wrong path. A fresh
  // record is needed, not reuse of a packet number at a new address.
  CHECK(!server.receive(from,*confirm.reply,0).reply);
  auto ready = server.receive(from,client.retry(1),1); CHECK(ready.reply && ready.activated);
  CHECK(client.state()==ClientState::connecting); // first READY deliberately lost
  ready = server.receive(from,client.retry(2),2); CHECK(ready.reply && !ready.activated);
  client.receive(endpoint(),ready.reply->datagram,2); CHECK(client.state()==ClientState::active);
}
void expired_challenge_recovers() {
  RemoteSession server(key(),0,policy()); SessionClient client(endpoint(),key(),0); auto from = endpoint(40000);
  auto challenge = server.receive(from,client.retry(0),0); CHECK(challenge.reply);
  CHECK(client.receive(endpoint(),challenge.reply->datagram,0).reply); // discard CONFIRM
  server.tick(101);
  for(std::uint64_t t=101; t<111 && client.state()!=ClientState::active; ++t) {
    auto answer = server.receive(from,client.retry(t),t);
    if(!answer.reply) continue;
    auto c = client.receive(endpoint(),answer.reply->datagram,t);
    if(c.reply) {
      auto ready=server.receive(from,*c.reply,t); CHECK(ready.reply);
      client.receive(endpoint(),ready.reply->datagram,t);
    }
  }
  CHECK(client.state()==ClientState::active);
}
void migration_and_sleep() {
  RemoteSession server(key(),0,policy()); SessionClient client(endpoint(),key(),0);
  auto old = endpoint(40000), moved = endpoint(40001); handshake(server,client,old,0);
  auto delayed=client.send({9},1); client.revalidate_path();
  auto h=client.retry(2); auto challenge=server.receive(moved,h,2); CHECK(challenge.reply);
  CHECK(server.peer()==std::optional<UdpEndpoint>(old));
  CHECK(server.receive(old,delayed,2).data==std::optional<Bytes>(Bytes{9}));
  auto proof=client.receive(endpoint(),challenge.reply->datagram,2); CHECK(proof.reply);
  auto ready=server.receive(moved,*proof.reply,2); CHECK(ready.migrated && !ready.activated);
  client.receive(endpoint(),ready.reply->datagram,2); CHECK(server.peer()==std::optional<UdpEndpoint>(moved));
  CHECK(!server.receive(old,h,3).reply && !server.receive(old,delayed,3).data);
  constexpr std::uint64_t six_months=180ULL*24*60*60*1000;
  server.tick(six_months); CHECK(server.state()==RemoteState::active);
  client.revalidate_path(); handshake(server,client,endpoint(40002),six_months);
}
void client_exhaustion_is_closed() {
  Policy crypto; crypto.rekey_packets=1; crypto.hard_packets=1;
  SessionClient client(endpoint(),key(),0,crypto);
  client.retry(0); client.retry(0); // epoch 0, then one unacknowledged epoch 1
  rejects([&]{client.retry(0);}); CHECK(client.state()==ClientState::closed);
  client.stop(); client.tick(1); CHECK(client.state()==ClientState::closed);
}
void close_and_idle() {
  auto p=policy(); RemoteSession server(key(),0,p); SessionClient client(endpoint(),key(),0); auto from=endpoint(40000);
  handshake(server,client,from,0);
  auto delayed=client.send({1},1); auto closed=server.receive(from,client.close(2),2);
  CHECK(closed.reply && closed.closing && server.state()==RemoteState::draining);
  CHECK(!server.receive(from,delayed,2).data);
  for(std::uint64_t t=3;t<52;++t) { auto ack=server.receive(from,client.retry(t),t); CHECK(ack.reply); }
  server.tick(52); CHECK(server.state()==RemoteState::closed);
  client.receive(endpoint(),closed.reply->datagram,52); CHECK(client.state()==ClientState::closed);
  rejects([&]{client.retry(52);});
  p.idle_ms=50; RemoteSession idle(key(),0,p); SessionClient c(endpoint(),key(),0); handshake(idle,c,from,0);
  auto stale=c.send({1},1); CHECK(idle.receive(from,c.send({2},2),2).data);
  CHECK(idle.receive(from,stale,40).data); // reordered data must not renew idle lease
  idle.tick(52); CHECK(idle.state()==RemoteState::closed);
}
}
int main() {
  try { addresses(); startup_cannot_be_renewed(); data_and_reorder(); forged_path_and_lost_ready(); expired_challenge_recovers(); migration_and_sleep(); close_and_idle(); client_exhaustion_is_closed();
    std::cout<<"PASS numeric endpoints, startup expiry, return-path proof, loss recovery, migration, reordering, logical sleep, closure and idle policy\n"; return 0;
  } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
