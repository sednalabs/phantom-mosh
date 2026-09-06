// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
#include "record.h"
#include "crypto_internal.h"
#include <algorithm>
#include <array>
#include <functional>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
using namespace phantom;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string(__func__) + ":" + std::to_string(__LINE__) + ": " #x); } while (false)
static constexpr auto BOOT = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
static Bootstrap key() { return Bootstrap::parse(BOOT); }
static Bytes bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }
static Bytes hex(std::string_view s) {
  CHECK(s.size() % 2 == 0);
  Bytes out;
  for (std::size_t i = 0; i < s.size(); i += 2) out.push_back(static_cast<unsigned char>(std::stoul(std::string(s.substr(i, 2)), nullptr, 16)));
  return out;
}
static std::string hexstr(const Bytes& v) {
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string out;
  for (auto c : v) { out += alphabet[c >> 4]; out += alphabet[c & 15]; }
  return out;
}
template<class F> static void rejects(F&& f) {
  bool rejected = false;
  try { f(); } catch (const Error&) { rejected = true; }
  CHECK(rejected);
}
static Policy fast() { Policy p; p.rekey_packets = 4; p.hard_packets = 32; p.rekey_ms = 100; p.previous_key_ms = 20; return p; }
static void same_protocol_state(StateView a, StateView b) {
  CHECK(a.send_epoch == b.send_epoch && a.receive_epoch == b.receive_epoch && a.peer_ack == b.peer_ack);
  CHECK(a.sent_in_epoch == b.sent_in_epoch && a.previous_key_retained == b.previous_key_retained && a.closed == b.closed);
}
static void known_answers() {
  // RFC 5869 A.1; expected values are independent of this implementation.
  Bytes ikm(22, 0x0b), salt = hex("000102030405060708090a0b0c"), info = hex("f0f1f2f3f4f5f6f7f8f9");
  std::array<unsigned char, 32> prk{};
  detail::extract(ikm.data(), ikm.size(), salt.data(), salt.size(), prk.data());
  CHECK(Bytes(prk.begin(), prk.end()) == hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
  Bytes okm(42);
  detail::expand(prk.data(), info.data(), info.size(), okm.data(), okm.size());
  CHECK(okm == hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
  // RFC 9001 A.5: first five mask bytes; this draft uses eight.
  const auto hp = hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
  const auto sample = hex("5e5cd55c41f69080575d7999c25a5bfb");
  const auto mask = detail::mask(hp.data(), sample.data());
  CHECK(Bytes(mask.begin(), mask.begin() + 5) == hex("aefefe7d03"));
  // RFC 8439 2.8.2, including the full authentication tag.
  const auto k = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const auto n = hex("070000004041424344454647");
  const auto aad = hex("50515253c0c1c2c3c4c5c6c7");
  const auto text = bytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const auto expected = hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
  CHECK(detail::encrypt(k.data(), n.data(), aad, text) == expected);
  CHECK(detail::decrypt(k.data(), n.data(), aad, expected) == std::optional<Bytes>(text));
  const auto empty = detail::encrypt(k.data(), n.data(), {}, {});
  CHECK(empty.size() == 16 && detail::decrypt(k.data(), n.data(), {}, empty)->empty());
}
static void bootstrap_lifetime() {
  static_assert(!std::is_copy_constructible_v<Bootstrap> && !std::is_copy_constructible_v<Session>);
  static_assert(!std::is_move_constructible_v<Session>);
  auto first = key(); auto text = first.encode(); CHECK(std::string_view(text.data(), text.size()) == BOOT);
  auto second = std::move(first); CHECK(!first.valid() && second.valid());
  rejects([&] { first.encode(); });
  Session client(Role::client, std::move(second), 0); CHECK(!second.valid());
  rejects([&] { Session invalid(Role::client, std::move(second), 0); });
  for (const auto& bad : {std::string(42, 'A'), std::string(44, 'A'), std::string(43, '-'), std::string(42, 'A') + "B", std::string(42, 'A') + "\n"})
    rejects([&] { Bootstrap::parse(bad); });
  auto random = Bootstrap::random(); auto wire = random.encode();
  auto parsed = Bootstrap::parse(std::string_view(wire.data(), wire.size()));
  auto again = parsed.encode(); CHECK(std::string_view(wire.data(), wire.size()) == std::string_view(again.data(), again.size()));
  auto bad_policy = fast(); bad_policy.hard_packets = 0;
  auto consumed = key(); rejects([&] { Session bad(Role::client, std::move(consumed), 0, bad_policy); }); CHECK(!consumed.valid());
}
static void lengths_directions_and_duplicates() {
  Session c(Role::client, key(), 0), s(Role::server, key(), 0), stranger(Role::server, Bootstrap::random(), 0);
  for (std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{7}, std::size_t{8}, MAX_PAYLOAD}) {
    Bytes payload(n, 0x51); auto wire = c.seal(payload, 0); CHECK(wire.size() == n + RECORD_OVERHEAD);
    CHECK(!c.open(wire, 0)); CHECK(!stranger.open(wire, 0));
    auto received = s.open(wire, 0); CHECK(received && received->payload == payload && received->newest);
    CHECK(!s.open(wire, 0));
  }
  const auto before = c.state(); rejects([&] { c.seal(Bytes(MAX_PAYLOAD + 1), 0); }); same_protocol_state(before, c.state());
  for (std::size_t n = 0; n < RECORD_OVERHEAD; ++n) CHECK(!s.open(Bytes(n), 0));
  CHECK(!s.open(Bytes(MAX_DATAGRAM + 1), 0));
}
static void every_byte_tamper() {
  Session c(Role::client, key(), 0), s(Role::server, key(), 0);
  const auto wire = c.seal(bytes("ciphertext, header and tag"), 0); const auto before = s.state();
  for (std::size_t i = 0; i < wire.size(); ++i) for (unsigned bit = 0; bit < 8; ++bit) {
    auto changed = wire; changed[i] ^= static_cast<unsigned char>(1U << bit);
    CHECK(!s.open(changed, 0)); CHECK(s.state().last_open_attempts <= 3); same_protocol_state(before, s.state());
  }
  CHECK(s.open(wire, 0));
}
static void reordering_and_replay_window() {
  Session c(Role::client, key(), 0), s(Role::server, key(), 0);
  auto oldest = c.seal(bytes("old"), 0);
  auto earlier = c.seal(bytes("earlier"), 0), later = c.seal(bytes("later"), 0);
  auto newest = s.open(later, 0); CHECK(newest && newest->newest);
  auto reordered = s.open(earlier, 0); CHECK(reordered && !reordered->newest); CHECK(!s.open(earlier, 0));
  Bytes end; for (std::size_t i = 0; i < REPLAY_WINDOW; ++i) end = c.seal({}, 0);
  CHECK(s.open(end, 0)); CHECK(!s.open(oldest, 0));
}
static void ack_gating_and_six_month_sleep() {
  const auto p = fast(); Session c(Role::client, key(), 0, p), s(Role::server, key(), 0, p);
  auto delayed = c.seal(bytes("late epoch zero"), 0), other_old = c.seal(bytes("retired"), 0);
  for (unsigned i = 0; i < 3; ++i) c.seal({}, 0);
  CHECK(c.state().send_epoch == 1 && c.state().peer_ack == 0);
  constexpr std::uint64_t six_months = 180ULL * 24 * 60 * 60 * 1000;
  auto reconnect = c.seal(bytes("resume"), six_months); CHECK(c.state().send_epoch == 1);
  auto r = s.open(reconnect, six_months); CHECK(r && r->epoch == 1);
  auto late = s.open(delayed, six_months); CHECK(late && !late->newest); CHECK(s.state().previous_key_retained);
  s.tick(six_months + p.previous_key_ms); CHECK(!s.state().previous_key_retained);
  CHECK(!s.open(other_old, six_months + p.previous_key_ms));
  auto ack = s.seal({}, six_months + p.previous_key_ms);
  CHECK(c.open(ack, six_months + p.previous_key_ms)); CHECK(c.state().peer_ack == 1);
  auto next = c.seal({}, six_months + p.previous_key_ms);
  CHECK(c.state().send_epoch == 2 && s.open(next, six_months + p.previous_key_ms));
}
static void simultaneous_updates() {
  auto p = fast(); p.rekey_packets = 1;
  Session c(Role::client, key(), 0, p), s(Role::server, key(), 0, p);
  CHECK(s.open(c.seal({}, 0), 0)); CHECK(c.open(s.seal({}, 0), 0));
  auto a = c.seal({}, 1), b = s.seal({}, 1); CHECK(c.state().send_epoch == 1 && s.state().send_epoch == 1);
  CHECK(s.open(a, 1) && c.open(b, 1));
  a = c.seal({}, 2); b = s.seal({}, 2); CHECK(c.state().send_epoch == 1 && s.state().send_epoch == 1);
  CHECK(s.open(a, 2) && c.open(b, 2)); CHECK(c.state().peer_ack == 1 && s.state().peer_ack == 1);
  CHECK(s.open(c.seal({}, 3), 3)); CHECK(c.open(s.seal({}, 3), 3));
  CHECK(c.state().send_epoch == 2 && s.state().send_epoch == 2);
}
static void hard_limits_and_closure() {
  auto p = fast(); p.rekey_packets = 1; p.hard_packets = 2; Session c(Role::client, key(), 0, p);
  c.seal({}, 0); c.seal({}, 0); c.seal({}, 0); rejects([&] { c.seal({}, 0); }); CHECK(c.state().closed);
  rejects([&] { c.open(Bytes(32), 0); }); c.close(); c.close();
  p.failed_verifications = 3; Session s(Role::server, key(), 0, p);
  CHECK(!s.open(Bytes(32), 0)); rejects([&] { s.open(Bytes(32), 0); }); CHECK(s.state().closed);
  Session clock(Role::client, key(), 50); rejects([&] { clock.seal({}, 49); }); CHECK(!clock.state().closed);
}
// Test-only raw keys construct valid-AEAD records with invalid protocol fields.
static Bytes forged_protocol_record(std::uint64_t pn, std::uint32_t ack, std::uint32_t epoch = 0) {
  Bytes root(32); for (unsigned i = 0; i < 32; ++i) root[i] = static_cast<unsigned char>(i);
  const auto salt = bytes("phantom-mosh/v3/draft-01"); std::array<unsigned char, 32> master{}, traffic{}, k{}, hp{};
  std::array<unsigned char, 12> iv{};
  detail::extract(root.data(), root.size(), salt.data(), salt.size(), master.data());
  auto derive = [](const unsigned char* secret, std::string_view label, unsigned char* out, std::size_t n) {
    detail::expand(secret, reinterpret_cast<const unsigned char*>(label.data()), label.size(), out, n);
  };
  derive(master.data(), "client to server", traffic.data(), 32);
  derive(traffic.data(), "traffic key", k.data(), 32); derive(traffic.data(), "traffic iv", iv.data(), 12);
  derive(traffic.data(), "header protection", hp.data(), 32); Bytes aad(8), plain(8);
  for (unsigned i = 0; i < 8; ++i) { aad[7-i] = static_cast<unsigned char>(pn >> (8*i)); iv[11-i] ^= aad[7-i]; }
  for (unsigned i = 0; i < 4; ++i) { plain[3-i] = static_cast<unsigned char>(epoch >> (8*i)); plain[7-i] = static_cast<unsigned char>(ack >> (8*i)); }
  const auto ct = detail::encrypt(k.data(), iv.data(), aad, plain); const auto mask = detail::mask(hp.data(), ct.data());
  for (unsigned i = 0; i < 8; ++i) aad[i] ^= mask[i]; aad.insert(aad.end(), ct.begin(), ct.end()); return aad;
}
static void authenticated_invalid_fields_are_atomic() {
  Session s(Role::server, key(), 0); auto before = s.state();
  CHECK(!s.open(forged_protocol_record(900, 1), 0)); same_protocol_state(before, s.state());
  CHECK(!s.open(forged_protocol_record(900, 0, 7), 0)); same_protocol_state(before, s.state());
  CHECK(!s.open(forged_protocol_record(MAX_PACKET_NUMBER + 1, 0), 0)); same_protocol_state(before, s.state());
  CHECK(s.open(forged_protocol_record(0, 0), 0));
}
static void deterministic_network_schedule() {
  Policy p; p.rekey_packets = 13; p.hard_packets = 10000; p.rekey_ms = 50; p.previous_key_ms = 120000;
  Session c(Role::client, key(), 0, p), s(Role::server, key(), 0, p); std::mt19937_64 random(0x5048414e544f4dULL);
  struct InFlight { bool from_client; Bytes record; }; std::vector<InFlight> pending;
  std::set<std::pair<bool, std::uint64_t>> accepted; std::size_t delivered = 0;
  for (std::uint64_t t = 0; t < 10000; ++t) {
    for (bool client : {false, true}) {
      auto& sender = client ? c : s; auto wire = sender.seal(bytes("terminal state delta"), t);
      if (random() % 5 != 0) pending.push_back({client, wire});
      if (random() % 7 == 0) pending.push_back({client, wire});
    }
    for (unsigned n = 0; n < 3 && !pending.empty(); ++n) {
      const auto index = static_cast<std::size_t>(random() % pending.size());
      auto packet = std::move(pending[index]); pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(index));
      auto& receiver = packet.from_client ? s : c;
      if (random() % 11 == 0) { auto bad = packet.record; bad.back() ^= 1; CHECK(!receiver.open(bad, t)); }
      auto result = receiver.open(packet.record, t); CHECK(receiver.state().last_open_attempts <= 3);
      if (result) { CHECK(result->payload == bytes("terminal state delta")); CHECK(accepted.emplace(packet.from_client, result->packet_number).second); ++delivered; }
    }
    CHECK(c.state().send_epoch <= s.state().receive_epoch + 1); CHECK(s.state().send_epoch <= c.state().receive_epoch + 1);
  }
  for (std::uint64_t t = 10000; t < 10010; ++t) {
    CHECK(s.open(c.seal(bytes("final client state"), t), t)); CHECK(c.open(s.seal(bytes("final server state"), t), t));
  }
  CHECK(delivered > 10000 && c.state().send_epoch > 100 && s.state().send_epoch > 100);
}
int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--vectors") {
      Policy p; p.rekey_packets = 1; Session c(Role::client, key(), 0, p), s(Role::server, key(), 0, p);
      auto c0 = c.seal({}, 0); CHECK(s.open(c0, 0)); auto s0 = s.seal(bytes("hello"), 0); CHECK(c.open(s0, 0));
      auto c1 = c.seal(bytes("epoch one"), 0); CHECK(s.open(c1, 0)); auto s1 = s.seal(bytes("ack one"), 0); CHECK(c.open(s1, 0));
      auto c2 = c.seal(bytes("epoch two"), 0); CHECK(s.open(c2, 0)); auto s2 = s.seal(bytes("ack two"), 0); CHECK(c.open(s2, 0));
      auto maximum = c.seal(Bytes(MAX_PAYLOAD, 0x51), 0); CHECK(s.open(maximum, 0));
      std::cout << "{\"empty_client\":\"" << hexstr(c0) << "\",\"hello_server\":\"" << hexstr(s0)
                << "\",\"client_epoch_one\":\"" << hexstr(c1) << "\",\"server_epoch_one\":\"" << hexstr(s1)
                << "\",\"client_epoch_two\":\"" << hexstr(c2) << "\",\"server_epoch_two\":\"" << hexstr(s2)
                << "\",\"maximum_client_epoch_three\":\"" << hexstr(maximum) << "\"}\n"; return 0;
    }
    const std::pair<const char*, std::function<void()>> tests[] = {
      {"RFC known answers", known_answers}, {"bootstrap lifetime", bootstrap_lifetime},
      {"lengths/directions/replays", lengths_directions_and_duplicates}, {"every bit tamper", every_byte_tamper},
      {"replay window", reordering_and_replay_window}, {"six-month logical sleep", ack_gating_and_six_month_sleep},
      {"simultaneous updates", simultaneous_updates}, {"hard limits", hard_limits_and_closure},
      {"authenticated invalid fields", authenticated_invalid_fields_are_atomic}, {"seeded network schedule", deterministic_network_schedule}
    };
    for (const auto& test : tests) { test.second(); std::cout << "PASS " << test.first << '\n'; } return 0;
  } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
