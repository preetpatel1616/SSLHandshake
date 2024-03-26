#ifndef CRYPTO_ADAPTOR_H
#define CRYPTO_ADAPTOR_H

#include <openssl/bn.h>
#include <string>
#include <vector>

//////////////////////////////////////////////
// DHE
int generate_dh_parameters(SSL_CTX *ctx);

//////////////////////////////////////////////
// RSA
// int generate_rsa_keys(CryptoPP::RSA::PrivateKey &private_key, CryptoPP::RSA::PublicKey &public_key);

//////////////////////////////////////////////
// Encryption
bool aes_encrypt(const std::string &plaintext, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, std::string &ciphertext);

bool aes_decrypt(const std::string &ciphertext, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, std::string &plaintext);

// int rsa_encrypt(const CryptoPP::RSA::PublicKey &pub_key,
//                 std::string *cipher_text, const std::string &plain_text);

// int rsa_decrypt(const CryptoPP::RSA::PrivateKey &priv_key,
//                 std::string *plain_text, const std::string &cipher_text);
uint32_t generate_random_number();

void append_BN_to_vector(const BIGNUM *bn, std::vector<uint8_t> &vec);
std::vector<uint8_t> BIGNUM_to_vector(const BIGNUM *bn);
#endif // CRYPTO_ADAPTOR_H
