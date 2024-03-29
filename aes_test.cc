#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <string.h>

bool aes_encrypt(const std::string &plaintext, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, std::string &ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<uint8_t> buffer(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, buffer.data(), &len, reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, buffer.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    buffer.resize(ciphertext_len);
    ciphertext.assign(buffer.begin(), buffer.end());

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_decrypt(const std::string &ciphertext, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, std::string &plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<uint8_t> buffer(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, buffer.data(), &len, reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, buffer.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    buffer.resize(plaintext_len);
    plaintext.assign(buffer.begin(), buffer.end());

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

int main()
{
    std::vector<uint8_t> key(16); // AES-128 uses 16-byte keys
    std::vector<uint8_t> iv(16);  // AES block size is 16 bytes

    // Generate a random key and IV for testing
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), iv.size());
    
    std::string plaintext = "\xAB\xCD\xEF";
    std::string encrypted, decrypted;

    if (aes_encrypt(plaintext, key, iv, encrypted))
    {
        std::cout << "Encryption successful" << std::endl;
    }
    else
    {
        std::cout << "Encryption failed" << std::endl;
        return 1;
    }

    if (aes_decrypt(encrypted, key, iv, decrypted))
    {
        std::cout << "Decryption successful" << std::endl;
        std::cout << "Decrypted text: " << decrypted << std::endl;
    }
    else
    {
        std::cout << "Decryption failed" << std::endl;
        return 1;
    }

    return 0;
}
