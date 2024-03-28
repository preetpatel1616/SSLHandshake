#include "crypto_adaptor.h"

#include <iostream>
#include <vector>
#include <string.h>

#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/evp.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

using namespace std;

// DHE Parameters
int generate_dh_parameters(SSL_CTX *ctx)
{
  int ret = 0;
  DH *dh = DH_new();
  // Use OpenSSL's predefined DH parameters
  DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);
  SSL_CTX_set_tmp_dh(ctx, dh);
  DH_free(dh);
  return 0;
}

// AES encryption and decryption
bool aes_encrypt(const std::string &plaintext, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, std::string &ciphertext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return false;

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
  {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  // Prepare a vector to hold the encrypted data temporarily
  std::vector<uint8_t> buffer(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
  int len = 0;
  int ciphertext_len = 0;

  if (1 != EVP_EncryptUpdate(ctx, buffer.data(), &len, reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size()))
  {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, buffer.data() + len, &len))
  {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len += len;

  // Resize the buffer to the actual ciphertext length
  buffer.resize(ciphertext_len);

  // Convert the buffer to a string and assign it to the output ciphertext
  ciphertext.assign(buffer.begin(), buffer.end());

  EVP_CIPHER_CTX_free(ctx);
  return true;
}
bool aes_decrypt(const string &ciphertext, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, std::string &plaintext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return false;

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
  {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  // Prepare a vector to hold the decrypted data temporarily
  std::vector<uint8_t> buffer(ciphertext.size());
  int len = 0;
  int plaintext_len = 0;

  if (1 != EVP_DecryptUpdate(ctx, buffer.data(), &len, reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size()))
  {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, buffer.data() + len, &len))
  {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  plaintext_len += len;

  // Resize the buffer to the actual plaintext length
  buffer.resize(plaintext_len);

  // Convert the buffer to a string and assign it to the output plaintext
  plaintext.assign(buffer.begin(), buffer.end());

  EVP_CIPHER_CTX_free(ctx);
  return true;
}

uint32_t generate_random_number()
{
  std::vector<unsigned char> random_data(sizeof(uint32_t)); // sizeof(uint32_t) is typically 4 bytes
  int rc = RAND_bytes(random_data.data(), random_data.size());
  if (rc != 1)
  {
    // Handle error: the random number generator failed
    throw std::runtime_error("Random number generation failed");
  }

  // Combine the 4 bytes into a single uint32_t value
  uint32_t result = 0;
  for (int i = 0; i < 4; ++i)
  {
    result |= static_cast<uint32_t>(random_data[i]) << (8 * i);
  }

  return result;
}

void append_BN_to_vector(const BIGNUM *bn, std::vector<uint8_t> &vec)
{
  // Check the size needed for the BIGNUM
  int numBytes = BN_num_bytes(bn);

  // Temporary buffer to hold BIGNUM bytes
  std::vector<uint8_t> tmp(numBytes);

  // Convert BIGNUM to byte array
  BN_bn2bin(bn, tmp.data());

  // Append the bytes to the vector
  vec.insert(vec.end(), tmp.begin(), tmp.end());
}

std::vector<uint8_t> BIGNUM_to_vector(const BIGNUM *bn)
{
  if (!bn)
    return {};
  int bn_len = BN_num_bytes(bn);
  std::vector<uint8_t> vec(bn_len);
  BN_bn2bin(bn, vec.data()); // Convert BIGNUM to binary and store in vector
  return vec;
}

BIGNUM *vector_to_BIGNUM(const std::vector<uint8_t> &vec)
{
  if (vec.empty())
  {
    return nullptr;
  }

  // BN_bin2bn converts an array of bytes in big-endian order to a BIGNUM.
  // The parameters are the byte array, its length, and an optional pre-allocated BIGNUM to use.
  // If the third parameter is NULL, a new BIGNUM is created and returned.
  BIGNUM *bn = BN_bin2bn(vec.data(), vec.size(), NULL);

  return bn;
}

EVP_PKEY *BIGNUMs_to_EVP_PKEY_DH(const BIGNUM *p, const BIGNUM *g, const BIGNUM *pub_key)
{
  EVP_PKEY *dh_pkey = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
  if (pctx == NULL)
  {
    std::cerr << "Failed to create EVP_PKEY_CTX for DH" << std::endl;
    return NULL;
  }

  OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
  if (param_bld == NULL)
  {
    std::cerr << "Failed to create OSSL_PARAM_BLD" << std::endl;
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }

  if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p) ||
      !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g) ||
      !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pub_key))
  {
    std::cerr << "Failed to add DH parameters" << std::endl;
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }

  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
  if (params == NULL)
  {
    std::cerr << "Failed to convert BLD to PARAM" << std::endl;
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }

  if (EVP_PKEY_fromdata_init(pctx) <= 0)
  {
    std::cerr << "Failed to initialize fromdata" << std::endl;
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }

  if (EVP_PKEY_fromdata(pctx, &dh_pkey, EVP_PKEY_KEYPAIR, params) <= 0)
  {
    std::cerr << "Failed to generate DH key from data" << std::endl;
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }

  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(param_bld);
  EVP_PKEY_CTX_free(pctx);

  return dh_pkey;
}
