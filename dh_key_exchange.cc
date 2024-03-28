#include <iostream>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <vector>

// g++ dh_key_exchange.cc -o dh_key_exchange -lcrypto -std=c++11

// Utility function to convert a BIGNUM to a vector of bytes
std::vector<uint8_t> BIGNUM_to_vector(const BIGNUM *bn)
{
    if (!bn)
        return {};
    int bn_len = BN_num_bytes(bn);
    std::vector<uint8_t> vec(bn_len);
    BN_bn2bin(bn, vec.data());
    return vec;
}

int send_key_exchange()
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx)
    {
        std::cerr << "Failed to create EVP_PKEY_CTX for parameters generation" << std::endl;
        return -1;
    }

    // Generate DH parameters
    if (EVP_PKEY_paramgen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 1024) <= 0)
    {
        std::cerr << "Failed to initialize parameter generation or set prime length" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0)
    {
        std::cerr << "Failed to generate parameters" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx); // No longer needed

    // Generate DH key pair
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY *dhkey = NULL;
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &dhkey) <= 0)
    {
        std::cerr << "Failed to initialize or generate key pair" << std::endl;
        EVP_PKEY_free(params);
        if (kctx)
            EVP_PKEY_CTX_free(kctx);
        return -1;
    }

    // Access and print the generated values
    BIGNUM *p = NULL, *g = NULL, *pub_key = NULL, *priv_key = NULL;
    EVP_PKEY_get_bn_param(params, "p", &p);
    EVP_PKEY_get_bn_param(params, "g", &g);
    EVP_PKEY_get_bn_param(dhkey, "pub", &pub_key);
    EVP_PKEY_get_bn_param(dhkey, "priv", &priv_key);

    auto p_vec = BIGNUM_to_vector(p);
    auto g_vec = BIGNUM_to_vector(g);
    auto pub_key_vec = BIGNUM_to_vector(pub_key);
    auto priv_key_vec = BIGNUM_to_vector(priv_key);

    // Normally, you would now send 'pub_key_vec' to the peer and receive the peer's public key to compute the shared secret

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_free(dhkey);
    return 0;
}

int main()
{
    if (send_key_exchange() == 0)
    {
        std::cout << "Key exchange successful" << std::endl;
    }
    else
    {
        std::cout<< "Key exchange failed" << std::endl;
    }
    return 0;
}
