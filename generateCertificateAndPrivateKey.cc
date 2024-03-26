#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <iostream>

int generate_certificate_and_key(const std::string &cert_file, const std::string &key_file)
{
    int ret = 0;
    EVP_PKEY *pkey = nullptr;
    X509 *x509 = nullptr;

    // Context for the key generation
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0)
    {
        std::cerr << "Error initializing key generation context\n";
        ret = -1;
        exit(1);
    }

    // Generate key
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        std::cerr << "Error generating RSA key\n";
        ret = -1;
        exit(1);
    }

    // Generate X509 certificate
    x509 = X509_new();
    if (!x509)
    {
        std::cerr << "Error creating X509 object\n";
        ret = -1;
        exit(1);
    }

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year

    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

    X509_set_issuer_name(x509, name); // self-signed

    if (!X509_sign(x509, pkey, EVP_sha256()))
    {
        std::cerr << "Error signing certificate\n";
        ret = -1;
        exit(1);
    }

    // Write certificate to file
    FILE *f_cert = fopen(cert_file.c_str(), "wb");
    if (!f_cert)
    {
        std::cerr << "Error opening certificate file for writing\n";
        ret = -1;
        exit(1);
    }
    PEM_write_X509(f_cert, x509);
    fclose(f_cert);

    // Write key to file
    FILE *f_key = fopen(key_file.c_str(), "wb");
    if (!f_key)
    {
        std::cerr << "Error opening key file for writing\n";
        ret = -1;
        exit(1);
    }
    PEM_write_PrivateKey(f_key, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(f_key);

end:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (x509)
        X509_free(x509);

    return ret;
}

int main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::string cert_file = "server_certificate.pem";
    std::string key_file = "server_private_key.pem";

    if (generate_certificate_and_key(cert_file, key_file) != 0)
    {
        std::cerr << "Failed to generate certificate and key\n";
        return 1;
    }

    std::cout << "Certificate and key generated successfully.\n";

    return 0;
}
