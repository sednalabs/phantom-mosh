// SPDX-License-Identifier: GPL-3.0-or-later
// Additional permission to link with OpenSSL: see COPYING.phantom.
// Internal primitives exposed only for independent known-answer tests.
#ifndef PHANTOM_MOSH_CRYPTO_INTERNAL_H
#define PHANTOM_MOSH_CRYPTO_INTERNAL_H
#include "record.h"
namespace phantom::detail {
void extract(const unsigned char* key, std::size_t key_len, const unsigned char* salt,
             std::size_t salt_len, unsigned char out[32]);
void expand(const unsigned char key[32], const unsigned char* info, std::size_t info_len,
            unsigned char* out, std::size_t out_len);
std::array<unsigned char, 8> mask(const unsigned char key[32], const unsigned char sample[16]);
Bytes encrypt(const unsigned char key[32], const unsigned char nonce[12], const Bytes& aad, const Bytes& plaintext);
std::optional<Bytes> decrypt(const unsigned char key[32], const unsigned char nonce[12], const Bytes& aad, const Bytes& ciphertext);
}
#endif
