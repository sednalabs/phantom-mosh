// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Copyright 2026 Phantom Mosh contributors
#include "record.h"
#include "crypto_internal.h"
#include <algorithm>
#include <bitset>
#include <cstring>
#include <limits>
#include <utility>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
namespace phantom {
namespace {
template<std::size_t N> struct Secret {
  std::array<unsigned char, N> bytes{};
  ~Secret() { clear(); }
  Secret() = default;
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  Secret(Secret&& other) noexcept : bytes(other.bytes) { other.clear(); }
  Secret& operator=(Secret&& other) noexcept {
    if (this != &other) { clear(); bytes = other.bytes; other.clear(); }
    return *this;
  }
  void clear() noexcept { OPENSSL_cleanse(bytes.data(), N); }
  unsigned char* data() noexcept { return bytes.data(); }
  const unsigned char* data() const noexcept { return bytes.data(); }
};
struct WipedBytes {
  Bytes bytes;
  explicit WipedBytes(std::size_t n) : bytes(n) {}
  explicit WipedBytes(Bytes&& value) noexcept : bytes(std::move(value)) {}
  WipedBytes(const WipedBytes&) = delete;
  WipedBytes& operator=(const WipedBytes&) = delete;
  ~WipedBytes() { if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
using Cipher = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using Kdf = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
void require(bool good) { if (!good) throw Error("cryptographic provider failure"); }
int bounded_int(std::size_t n) {
  if (n > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw Error("input too large");
  return static_cast<int>(n);
}
void put(unsigned char* out, std::uint64_t n, std::size_t size) {
  for (std::size_t i = size; i != 0; --i) { out[i - 1] = static_cast<unsigned char>(n); n >>= 8; }
}
std::uint64_t get(const unsigned char* in, std::size_t size) {
  std::uint64_t out = 0;
  for (std::size_t i = 0; i < size; ++i) out = (out << 8) | in[i];
  return out;
}
void label(const unsigned char* key, const char* text, unsigned char* out, std::size_t size) {
  detail::expand(key, reinterpret_cast<const unsigned char*>(text), std::strlen(text), out, size);
}
struct Epoch {
  Secret<32> secret, key, hp;
  Secret<12> iv;
  std::uint32_t number;
  Epoch(Secret<32>&& s, std::uint32_t n) : secret(std::move(s)), number(n) {
    label(secret.data(), "traffic key", key.data(), 32);
    label(secret.data(), "traffic iv", iv.data(), 12);
    label(secret.data(), "header protection", hp.data(), 32);
  }
  std::unique_ptr<Epoch> next() const {
    if (number == std::numeric_limits<std::uint32_t>::max()) return nullptr;
    Secret<32> s;
    label(secret.data(), "traffic update", s.data(), 32);
    return std::make_unique<Epoch>(std::move(s), number + 1);
  }
  std::array<unsigned char, 12> nonce(std::uint64_t pn) const {
    auto out = iv.bytes;
    unsigned char encoded[8]; put(encoded, pn, 8);
    for (std::size_t i = 0; i < 8; ++i) out[i + 4] ^= encoded[i];
    return out;
  }
};
struct Replay {
  std::bitset<REPLAY_WINDOW> seen;
  std::uint64_t highest = 0;
  bool initialized = false;
  bool fresh(std::uint64_t pn) const noexcept {
    if (!initialized || pn > highest) return true;
    const auto delta = highest - pn;
    return delta < REPLAY_WINDOW && !seen[static_cast<std::size_t>(delta)];
  }
  void accept(std::uint64_t pn) noexcept {
    if (!initialized) { initialized = true; highest = pn; seen.reset(); }
    if (pn > highest) {
      const auto delta = pn - highest;
      if (delta >= REPLAY_WINDOW) seen.reset(); else seen <<= static_cast<std::size_t>(delta);
      highest = pn;
    }
    seen.set(static_cast<std::size_t>(highest - pn));
  }
};
} // namespace
namespace detail {
void extract(const unsigned char* key, std::size_t key_len, const unsigned char* salt,
             std::size_t salt_len, unsigned char out[32]) {
  Kdf ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
  require(ctx && EVP_PKEY_derive_init(ctx.get()) > 0
    && EVP_PKEY_CTX_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) > 0
    && EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) > 0
    && EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt, bounded_int(salt_len)) > 0
    && EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key, bounded_int(key_len)) > 0);
  std::size_t size = 32;
  require(EVP_PKEY_derive(ctx.get(), out, &size) > 0 && size == 32);
}
void expand(const unsigned char key[32], const unsigned char* info, std::size_t info_len,
            unsigned char* out, std::size_t out_len) {
  Kdf ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
  require(ctx && EVP_PKEY_derive_init(ctx.get()) > 0
    && EVP_PKEY_CTX_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0
    && EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) > 0
    && EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key, 32) > 0
    && EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info, bounded_int(info_len)) > 0);
  auto size = out_len;
  require(EVP_PKEY_derive(ctx.get(), out, &size) > 0 && size == out_len);
}
std::array<unsigned char, 8> mask(const unsigned char key[32], const unsigned char sample[16]) {
  // RFC 9001 5.4.4 initial state, extended to eight mask bytes. OpenSSL raw
  // ChaCha's 64/64 counter/nonce split has the same FIRST-block words as the
  // IETF 32/96 layout. No second block/counter carry is requested here.
  Cipher ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  std::array<unsigned char, 8> zeros{}, out{};
  int n = 0;
  require(ctx && EVP_EncryptInit_ex(ctx.get(), EVP_chacha20(), nullptr, key, sample) == 1
    && EVP_EncryptUpdate(ctx.get(), out.data(), &n, zeros.data(), 8) == 1 && n == 8);
  return out;
}
Bytes encrypt(const unsigned char key[32], const unsigned char nonce[12], const Bytes& aad, const Bytes& plaintext) {
  const int length = bounded_int(plaintext.size());
  Cipher ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  require(ctx && EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key, nonce) == 1);
  int n = 0;
  require(EVP_EncryptUpdate(ctx.get(), nullptr, &n, aad.data(), bounded_int(aad.size())) == 1);
  Bytes out(plaintext.size() + 16);
  int used = 0;
  if (length) require(EVP_EncryptUpdate(ctx.get(), out.data(), &used, plaintext.data(), length) == 1);
  require(EVP_EncryptFinal_ex(ctx.get(), out.data() + used, &n) == 1 && used + n == length
    && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, out.data() + length) == 1);
  return out;
}
std::optional<Bytes> decrypt(const unsigned char key[32], const unsigned char nonce[12], const Bytes& aad, const Bytes& ciphertext) {
  if (ciphertext.size() < 16) return std::nullopt;
  const int length = bounded_int(ciphertext.size() - 16);
  Cipher ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  require(ctx && EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key, nonce) == 1);
  int n = 0;
  require(EVP_DecryptUpdate(ctx.get(), nullptr, &n, aad.data(), bounded_int(aad.size())) == 1);
  WipedBytes out(static_cast<std::size_t>(length) + 16);
  int used = 0;
  if (length) require(EVP_DecryptUpdate(ctx.get(), out.bytes.data(), &used, ciphertext.data(), length) == 1);
  Secret<16> tag;
  std::copy(ciphertext.end() - 16, ciphertext.end(), tag.bytes.begin());
  require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag.data()) == 1);
  if (EVP_DecryptFinal_ex(ctx.get(), out.bytes.data() + used, &n) != 1) return std::nullopt;
  require(used + n == length);
  return Bytes(out.bytes.begin(), out.bytes.begin() + length);
}
} // namespace detail
BootstrapText::~BootstrapText() { OPENSSL_cleanse(text_.data(), text_.size()); }
BootstrapText::BootstrapText(BootstrapText&& other) noexcept : text_(other.text_) {
  OPENSSL_cleanse(other.text_.data(), other.text_.size());
}
BootstrapText& BootstrapText::operator=(BootstrapText&& other) noexcept {
  if (this != &other) {
    OPENSSL_cleanse(text_.data(), text_.size()); text_ = other.text_;
    OPENSSL_cleanse(other.text_.data(), other.text_.size());
  }
  return *this;
}
void Bootstrap::clear() noexcept { OPENSSL_cleanse(secret_.data(), secret_.size()); valid_ = false; }
Bootstrap::~Bootstrap() { clear(); }
Bootstrap::Bootstrap(Bootstrap&& other) noexcept : secret_(other.secret_), valid_(other.valid_) { other.clear(); }
Bootstrap& Bootstrap::operator=(Bootstrap&& other) noexcept {
  if (this != &other) { clear(); secret_ = other.secret_; valid_ = other.valid_; other.clear(); }
  return *this;
}
Bootstrap Bootstrap::random() {
  Bootstrap out;
  require(RAND_priv_bytes(out.secret_.data(), 32) == 1);
  out.valid_ = true;
  return out;
}
BootstrapText Bootstrap::encode() const {
  if (!valid_) throw Error("bootstrap already consumed");
  Secret<45> buffer;
  require(EVP_EncodeBlock(buffer.data(), secret_.data(), 32) == 44);
  BootstrapText out;
  std::copy_n(buffer.bytes.begin(), 43, out.text_.begin());
  return out;
}
Bootstrap Bootstrap::parse(std::string_view text) {
  if (text.size() != 43) throw Error("invalid bootstrap encoding");
  constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (char c : text) if (alphabet.find(c) == std::string_view::npos) throw Error("invalid bootstrap encoding");
  if ((alphabet.find(text.back()) & 3U) != 0) throw Error("noncanonical bootstrap encoding");
  Secret<44> padded;
  std::copy(text.begin(), text.end(), padded.bytes.begin()); padded.bytes[43] = '=';
  Secret<33> decoded;
  require(EVP_DecodeBlock(decoded.data(), padded.data(), 44) == 33);
  Bootstrap out;
  std::copy_n(decoded.bytes.begin(), 32, out.secret_.begin());
  out.valid_ = true;
  return out;
}
struct Session::Impl {
  Policy policy;
  std::unique_ptr<Epoch> tx, tx_next, rx, rx_next, rx_previous;
  Replay replay;
  std::uint64_t now, tx_started, previous_started = 0, tx_pn = 0, tx_count = 0, failures = 0;
  std::uint64_t epoch_first_seen = 0;
  std::uint32_t ack = 0;
  unsigned int attempts = 0;
  bool closed = false;
  explicit Impl(Policy p, std::uint64_t t) : policy(p), now(t), tx_started(t) {}
  void retire() noexcept { tx.reset(); tx_next.reset(); rx.reset(); rx_next.reset(); rx_previous.reset(); closed = true; }
  void time(std::uint64_t t) {
    if (closed) throw Error("session closed");
    if (t < now) throw Error("monotonic clock moved backwards");
    now = t;
    if (rx_previous && t - previous_started >= policy.previous_key_ms) rx_previous.reset();
  }
  [[noreturn]] void exhausted() { retire(); throw Error("session limit reached; fresh authenticated bootstrap required"); }
};
Session::Session(Role role, Bootstrap&& bootstrap, std::uint64_t now_ms, Policy policy) {
  Bootstrap owned = std::move(bootstrap);
  if (!owned.valid() || (role != Role::client && role != Role::server)) throw Error("invalid session initialization");
  if (!policy.rekey_packets || policy.hard_packets < policy.rekey_packets
      || policy.hard_packets > (std::uint64_t{1} << 24) || !policy.rekey_ms
      || !policy.previous_key_ms || policy.previous_key_ms > 120000
      || !policy.failed_verifications || policy.failed_verifications > (std::uint64_t{1} << 32)) {
    throw Error("invalid or weaker-than-draft policy");
  }
  auto state = std::make_unique<Impl>(policy, now_ms);
  static constexpr char salt[] = "phantom-mosh/v3/draft-01";
  Secret<32> master, client, server;
  detail::extract(owned.secret_.data(), 32, reinterpret_cast<const unsigned char*>(salt), sizeof(salt) - 1, master.data());
  owned.clear();
  label(master.data(), "client to server", client.data(), 32);
  label(master.data(), "server to client", server.data(), 32);
  master.clear();
  state->tx = std::make_unique<Epoch>(role == Role::client ? std::move(client) : std::move(server), 0);
  state->rx = std::make_unique<Epoch>(role == Role::client ? std::move(server) : std::move(client), 0);
  state->tx_next = state->tx->next(); state->tx->secret.clear();
  state->rx_next = state->rx->next(); state->rx->secret.clear();
  impl_ = std::move(state);
}
Session::~Session() = default;
void Session::tick(std::uint64_t now_ms) { impl_->time(now_ms); }
void Session::close() noexcept { impl_->retire(); }
StateView Session::state() const noexcept {
  const auto& s = *impl_;
  return {s.tx ? s.tx->number : 0, s.rx ? s.rx->number : 0, s.ack, s.tx_count,
          s.failures, s.attempts, bool(s.rx_previous), s.closed};
}
Bytes Session::seal(const Bytes& payload, std::uint64_t now_ms) {
  auto& s = *impl_;
  s.time(now_ms);
  if (payload.size() > MAX_PAYLOAD) throw Error("payload exceeds datagram budget");
  const bool due = s.tx_count >= s.policy.rekey_packets || now_ms - s.tx_started >= s.policy.rekey_ms;
  if (due && s.ack == s.tx->number) {
    if (!s.tx_next) s.exhausted();
    auto successor = s.tx_next->next();
    s.tx = std::move(s.tx_next); s.tx->secret.clear(); s.tx_next = std::move(successor);
    s.tx_started = now_ms; s.tx_count = 0;
  }
  if (s.tx_count >= s.policy.hard_packets || s.tx_pn > MAX_PACKET_NUMBER) s.exhausted();
  const auto pn = s.tx_pn++; ++s.tx_count; // burn even on provider/network failure
  Bytes aad(8); put(aad.data(), pn, 8);
  WipedBytes plain(8 + payload.size());
  put(plain.bytes.data(), s.tx->number, 4); put(plain.bytes.data() + 4, s.rx->number, 4);
  std::copy(payload.begin(), payload.end(), plain.bytes.begin() + 8);
  const auto nonce = s.tx->nonce(pn);
  auto ciphertext = detail::encrypt(s.tx->key.data(), nonce.data(), aad, plain.bytes);
  const auto mask = detail::mask(s.tx->hp.data(), ciphertext.data());
  Bytes packet(8 + ciphertext.size());
  for (std::size_t i = 0; i < 8; ++i) packet[i] = aad[i] ^ mask[i];
  std::copy(ciphertext.begin(), ciphertext.end(), packet.begin() + 8);
  return packet;
}
std::optional<Received> Session::open(const Bytes& datagram, std::uint64_t now_ms) {
  auto& s = *impl_;
  s.time(now_ms); s.attempts = 0;
  if (datagram.size() < RECORD_OVERHEAD || datagram.size() > MAX_DATAGRAM) return std::nullopt;
  const Bytes ciphertext(datagram.begin() + 8, datagram.end());
  Epoch* candidates[] = {s.rx.get(), s.rx_next.get(), s.rx_previous.get()};
  for (auto* candidate : candidates) {
    if (!candidate) continue;
    const auto mask = detail::mask(candidate->hp.data(), ciphertext.data());
    Bytes aad(8);
    for (std::size_t i = 0; i < 8; ++i) aad[i] = datagram[i] ^ mask[i];
    const auto pn = get(aad.data(), 8);
    const auto nonce = candidate->nonce(pn);
    ++s.attempts;
    auto decrypted = detail::decrypt(candidate->key.data(), nonce.data(), aad, ciphertext);
    if (!decrypted) {
      if (++s.failures >= s.policy.failed_verifications) s.exhausted();
      continue;
    }
    WipedBytes plain(std::move(*decrypted));
    const auto epoch = static_cast<std::uint32_t>(get(plain.bytes.data(), 4));
    const auto peer_ack = static_cast<std::uint32_t>(get(plain.bytes.data() + 4, 4));
    const bool advancing = candidate == s.rx_next.get();
    if (pn > MAX_PACKET_NUMBER || epoch != candidate->number || peer_ack > s.tx->number
        || !s.replay.fresh(pn)
        || (advancing && s.replay.initialized && pn <= s.replay.highest)
        || (candidate == s.rx_previous.get() && pn >= s.epoch_first_seen)) return std::nullopt;
    const bool newest = !s.replay.initialized || pn > s.replay.highest;
    // Prepare allocation/derivation before committing authenticated state.
    Received result{pn, epoch, newest, Bytes(plain.bytes.begin() + 8, plain.bytes.end())};
    std::unique_ptr<Epoch> successor;
    if (advancing) successor = s.rx_next->next();
    if (advancing) {
      s.rx_previous = std::move(s.rx); s.previous_started = now_ms;
      s.rx = std::move(s.rx_next); s.rx->secret.clear(); s.rx_next = std::move(successor);
      s.epoch_first_seen = pn;
    }
    s.replay.accept(pn);
    s.ack = std::max(s.ack, peer_ack);
    return result;
  }
  return std::nullopt;
}
} // namespace phantom
