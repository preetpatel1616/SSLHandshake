#include "SslClient.h"
#include "SslServer.h"
#include "crypto_adaptor.h"
#include "../common/Logger/Logger.h"
#include "../common/Utils/Utils.h"

#include "stdlib.h"
#include "string.h"

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <cstring>
#include <random>
#include <cstdint>

using namespace std;

// do we need loggers for client in both ssl and tls?

SslClient::SslClient()
{
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0)
  {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_client_" + datetime + ".log"));
  this->logger_->log("SslClient object created. Client Log at " + datetime);
  // this->tcp_->logger_ = this->logger_;

  // Initialize with supported versions
  supported_tls_versions.insert(TLS_1_0); // TLS 1.0
  supported_tls_versions.insert(TLS_1_1); // TLS 1.1
  supported_tls_versions.insert(TLS_1_2); // TLS 1.2
}
SslClient::SslClient(TCP *tcp, const SSLSharedInfo &sslSharedInfo)
    : Ssl(tcp), sslSharedInfo(sslSharedInfo)
{
  if (!tcp)
  {
    logger_->log("TCP pointer is null in SslClient constructor.");
  }
  else
  {
    logger_->log("TCP sockfd in SslClient constructor: " + std::to_string(tcp->sockfd_));
  }
}

SslClient::~SslClient()
{
  // deleting the socket
  if (this->tcp_->socket_close() != StatusCode::Success)
  {
    this->tcp_->logger_ = nullptr;
    delete[] this->tcp_;
    this->tcp_ = nullptr;
    if (this->logger_)
    {
      this->logger_->log("SslClient:deconstructor:Failed to close socket.");
    }
  }
  else
  {
    if (this->logger_)
    {
      this->logger_->log("SslClient:deconstructor:Socket closed successfully.");
    }
  }

  // deleting the logger object
  if (this->logger_)
  {
    this->logger_->log("SslClient:deconstructor:SslClient object is being destroyed.");
    delete this->logger_;
    this->logger_ = nullptr;
  }
}

StatusCode SslClient::send_hello()
{

  // Assure TCP connection and shared key are available
  if (!tcp_)
  {
    logger_->log("SslClient::send_hello: Missing TCP connection or shared key.");
    return StatusCode::Error;
  }

  // 1. Construct clientHello
  ClientHello clientHello;
  clientHello.tls_negotiate_version_ = *supported_tls_versions.rbegin();

  // clientHello.random_ = generate_random_uint32();
  clientHello.random_ = 0x12345678;
  clientHello.cipher_suites_ = supported_cipher_suites;

  // logger_->log("SslClient:send_hello: ClientHello Data\n");
  // logger_->log("\nSslClient:send_hello: Supported tls version: ");
  // logger_->log(std::to_string(clientHello.tls_negotiate_version_));
  // logger_->log("SslClient:send_hello: TLS 1_2: ");
  // logger_->log(std::to_string(TLS_1_2));
  // logger_->log("SslClient:send_hello: Client random: ");
  // logger_->log(std::to_string(clientHello.random_));
  // logger_->log("SslClient:send_hello: Supported cipher suites: ");
  // std::string myString(clientHello.cipher_suites_.begin(), clientHello.cipher_suites_.end());
  // logger_->log(myString);

  std::vector<uint16_t> supported_cipher_suites;

  // 2. Calculate buffer size
  size_t buffer_size = 1;                               // For handshake message type
  buffer_size += 2;                                     // For version
  buffer_size += 4;                                     // For random
  buffer_size += clientHello.cipher_suites_.size() * 2; // For cipher suites

  // 3. Serialize clientHello
  char *serializedClientHello = new char[buffer_size];
  size_t index = 0;

  // Handshake message type
  serializedClientHello[index++] = HS_CLIENT_HELLO;

  // Version
  serializedClientHello[index++] = static_cast<char>(clientHello.tls_negotiate_version_ >> 8);
  serializedClientHello[index++] = static_cast<char>(clientHello.tls_negotiate_version_ & 0xFF);

  // Random
  for (int i = 3; i >= 0; --i)
  {
    serializedClientHello[index++] = (clientHello.random_ >> (i * 8)) & 0xFF;
  }

  // Cipher suites
  for (const auto &cipherSuite : clientHello.cipher_suites_)
  {
    serializedClientHello[index++] = static_cast<char>(cipherSuite >> 8);
    serializedClientHello[index++] = static_cast<char>(cipherSuite & 0xFF);
  }

  // 3. Create a Record
  Record record;
  record.hdr.record_type = REC_HANDSHAKE;
  record.hdr.tls_version = TLS_1_2;
  record.hdr.data_size = static_cast<uint16_t>(buffer_size);
  record.data = serializedClientHello;

  StatusCode status = Ssl::socket_send_record(record, nullptr);

  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:send_hello:Failed to send ClientHello message.");
    delete[] record.data; // clean up dynamically allocated memory
    record.data = nullptr;
    return StatusCode::Error;
  }
  this->sslSharedInfo.client_random_ = clientHello.random_;

  delete[] record.data;
  record.data = nullptr;
  return StatusCode::Success;
}

StatusCode SslClient::receive_hello()
{
  // 1. Receive the record
  Record recv_record;
  StatusCode status = Ssl::socket_recv_record(&recv_record, nullptr);
  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:receive_hello: Failed to receive ServerHello message.");
    return StatusCode::Error;
  }

  // Deserialize the handshake message type
  if (recv_record.hdr.record_type != REC_HANDSHAKE)
  {
    logger_->log("SslClient:receive_hello: Received record is not a handshake message.");
    return StatusCode::Error;
  }

  // Initialize an index to track parsing position within received data
  size_t index = 0;

  // deserialize the handhsake message type first and process it
  uint8_t handshake_message_type = static_cast<uint8_t>(recv_record.data[index]);
  if (handshake_message_type != HS_SERVER_HELLO)
  {
    logger_->log("SslServer:receive_hello: The received handshake record is not server hello.");
    return StatusCode::Error;
  }
  index += sizeof(handshake_message_type);

  ServerHello serverHello;
  // 2.1 deserialize tls version
  serverHello.chosen_tls_version_ = static_cast<uint16_t>(recv_record.data[index] << 8) | (recv_record.data[index + 1]);
  index += sizeof(serverHello.chosen_tls_version_);
  // 2.2 deserialize random
  serverHello.random_ = 0;
  for (int i = 0; i < 4; ++i)
  {
    serverHello.random_ = (serverHello.random_ << 8) | static_cast<uint8_t>(recv_record.data[index + i]);
  }
  index += sizeof(serverHello.random_);

  // 2.3 deserialize the chosen ciphersuite

  serverHello.chosen_cipher_suite_ = static_cast<uint16_t>(recv_record.data[index] << 8) | recv_record.data[index + 1];
  index += sizeof(serverHello.chosen_cipher_suite_);

  // 2.2 deserialize client id
  int client_id = 0; // Should be initialized to 0, not 100
  for (int i = 0; i < 4; ++i)
  {
    client_id = (client_id << 8) | static_cast<uint8_t>(recv_record.data[index + i]);
  }
  index += sizeof(client_id);

  // process deserialized data
  this->sslSharedInfo.client_id_ = client_id;
  this->sslSharedInfo.chosen_tls_version_ = serverHello.chosen_tls_version_;
  this->sslSharedInfo.chosen_cipher_suite_ = serverHello.chosen_cipher_suite_;
  this->sslSharedInfo.server_random_ = serverHello.random_;
  // Clean up and return success
  delete[] recv_record.data;
  recv_record.data = nullptr;
  return StatusCode::Success;
}

StatusCode SslClient::receive_certificate()
{

  // 1. receive the certificate record
  Record recv_record;
  StatusCode status = this->socket_recv_record(&recv_record, nullptr);
  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:receiveCertificate: Failed to receive certificate.\n");
    return StatusCode::Error;
  }

  // Check if the received record is a Handshake and of type Certificate
  if (recv_record.hdr.record_type != REC_HANDSHAKE)
  {
    logger_->log("SslClient:receiveCertificate: Received record is not a Handshake record.");
    delete[] recv_record.data; // Clean up
    return StatusCode::Error;
  }

  // Extract the handshake message type
  uint8_t handshake_message_type = recv_record.data[0];
  if (handshake_message_type != HS_CERTIFICATE)
  {
    logger_->log("SslClient:receiveCertificate: Handshake message is not Certificate.");
    delete[] recv_record.data; // Clean up
    recv_record.data = nullptr;
    return StatusCode::Error;
  }

  // Skip the handshake type to parse the certificate
  const unsigned char *p = reinterpret_cast<unsigned char *>(recv_record.data + 1);
  long certLength = static_cast<long>(recv_record.hdr.data_size) - 1; // Adjust for the handshake type byte

  // d2i_X509 increments the pointer, so we keep a copy to free later
  const unsigned char *orig_p = p;

  X509 *cert = d2i_X509(NULL, &p, certLength);
  if (!cert)
  {
    logger_->log("SslClient:receiveCertificate: Failed to parse the certificate.");
    return StatusCode::Error;
  }

  // Store the server's certificate for later use
  this->sslSharedInfo.server_certificate_ = cert;
  // Set up the certificate store and add the trusted CAs
  X509_STORE *store = X509_STORE_new();
  X509_STORE_load_locations(store, "tst/server_certificate.pem", NULL); // self signed certificate
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  X509_STORE_CTX_init(ctx, store, cert, NULL);

  // Verify the certificate
  int verify = X509_verify_cert(ctx);
  if (verify != 1)
  {
    logger_->log("SslClient:receiveCertificate: Verification of the server certificate failed.");
    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);
    return StatusCode::Error;
  }

  X509_STORE_free(store);
  X509_STORE_CTX_free(ctx);

  return StatusCode::Success;
}

StatusCode SslClient::receive_key_exchange()
{
  // 1. Receive the record
  Record recv_record;
  StatusCode status = this->socket_recv_record(&recv_record, nullptr);
  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:receiveKeyExchange: Failed to receive Key Exchange data.");
    return StatusCode::Error;
  }
  // 2. Ensure it's a key exchange record
  if (recv_record.hdr.record_type != REC_HANDSHAKE)
  {
    logger_->log("SslClient:receiveKeyExchange: Received record is not a Key Exchange message.");
    return StatusCode::Error;
  }

  uint8_t handshake_message_type = recv_record.data[0];
  if (handshake_message_type != HS_SERVER_KEY_EXCHANGE)
  {
    logger_->log("SSLClient:receiveKeyExchange: Incorrect handshake message type.");
    return StatusCode::Error;
  }

  // Check if we're using DHE_RSA_WITH_AES_128_CBC_SHA
  if (this->sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    // Deserialize DHE parameters and server's public key from data
    const unsigned char *dataPtr = reinterpret_cast<const unsigned char *>(recv_record.data + 1); // Skipping message type                       // Adjusting for handshake message type
    size_t offset = 0;

    // Deserialize p, g, and server's public key from data
    std::vector<uint8_t> p_vec = readLengthPrefixedVector(dataPtr, offset);
    std::vector<uint8_t> g_vec = readLengthPrefixedVector(dataPtr, offset);
    std::vector<uint8_t> server_pub_key_der = readLengthPrefixedVector(dataPtr, offset);

    // Deserialize the server's public key from DER format
    EVP_PKEY *server_pub_key = nullptr;
    const unsigned char *pubKeyPtr = server_pub_key_der.data();
    server_pub_key = d2i_PUBKEY(nullptr, &pubKeyPtr, server_pub_key_der.size());
    if (!server_pub_key)
    {
      logger_->log("Failed to deserialize server's public DH key.");
      return StatusCode::Error;
    }

    // Convert vectors back to BIGNUM*
    BIGNUM *p = vector_to_BIGNUM(p_vec);
    BIGNUM *g = vector_to_BIGNUM(g_vec);

    // Convert BIGNUMs to OSSL_PARAM
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

    // Set DH parameters
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (EVP_PKEY_fromdata_init(pctx) <= 0)
    {
      logger_->log("Failed to initialize DH parameters.");
      // Cleanup
    }

    EVP_PKEY *param_key = NULL;
    if (EVP_PKEY_fromdata(pctx, &param_key, EVP_PKEY_KEY_PARAMETERS, params) <= 0)
    {
      logger_->log("Failed to set DH parameters.");
      // Cleanup
    }

    // Generate the client's DH key pair
    EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0 ||
        EVP_PKEY_keygen(keygen_ctx, &this->dhKeyPair) <= 0)
    {
      logger_->log("Failed to generate client's DH key pair.");
      // Cleanup
    }

    // Setup the context for deriving the shared secret
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(this->dhKeyPair, nullptr); // Use client's DH key pair
    if (!derive_ctx)
    {
      logger_->log("Failed to create context for deriving shared secret.");
      EVP_PKEY_free(this->dhKeyPair); // Assuming dhKeyPair is the client's key pair
      EVP_PKEY_free(server_pub_key);  // Free server's public key
      return StatusCode::Error;
    }

    if (EVP_PKEY_derive_init(derive_ctx) <= 0)
    {
      logger_->log("Failed to initialize shared secret derivation.");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(this->dhKeyPair);
      EVP_PKEY_free(server_pub_key);
      return StatusCode::Error;
    }

    // Set the peer's public key (server's public key) for the derivation process
    if (EVP_PKEY_derive_set_peer(derive_ctx, server_pub_key) <= 0)
    {
      logger_->log("Failed to set the server's public key for shared secret derivation.");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(this->dhKeyPair);
      EVP_PKEY_free(server_pub_key);
      return StatusCode::Error;
    }

    // Determine buffer length for the shared secret
    size_t secret_len = 0;
    if (EVP_PKEY_derive(derive_ctx, nullptr, &secret_len) <= 0)
    {
      logger_->log("Failed to determine the length of the shared secret.");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(this->dhKeyPair);
      EVP_PKEY_free(server_pub_key);
      return StatusCode::Error;
    }

    // Allocate the buffer and derive the shared secret
    std::vector<unsigned char> shared_secret(secret_len);

    if (EVP_PKEY_derive(derive_ctx, shared_secret.data(), &secret_len) <= 0)
    {
      logger_->log("Shared secret derivation failed.");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(this->dhKeyPair);
      EVP_PKEY_free(server_pub_key);
      return StatusCode::Error;
    }

    // Store the shared secret
    sslSharedInfo.pre_master_secret_.assign(shared_secret.begin(), shared_secret.end());
    sslSharedInfo.dh_p_ = BN_dup(p); // store p
    sslSharedInfo.dh_g_ = BN_dup(g);
    // dh key pair already stored

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(server_pub_key);
    return StatusCode::Success;
  }
}

StatusCode SslClient::receive_hello_done()
{
  // Receive the HelloDone record
  Record recv_record;
  StatusCode status = Ssl::socket_recv_record(&recv_record, nullptr);
  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:receiveHelloDone: Failed to receive HelloDone message.");
    return StatusCode::Error;
  }

  // Check if the received record is a HelloDone message
  if (recv_record.hdr.record_type != REC_HANDSHAKE)
  {
    logger_->log("SslClient:receiveHelloDone: Received record is not a handshake message.");
    return StatusCode::Error;
  }
  // Extract the handshake message type
  uint8_t handshake_message_type = recv_record.data[0];
  if (handshake_message_type != HS_SERVER_HELLO_DONE)
  {
    logger_->log("SslClient:receiveHelloDone: Incorrect handshake message type, expected ServerHelloDone.");
    return StatusCode::Error;
  }

  return StatusCode::Success;
}

StatusCode SslClient::send_key_exchange()
{
  if (this->sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    // Serialize the public key of the client's DH key pair to DER format
    unsigned char *pubKeyDER = nullptr; // Pointer to DER encoded public key
    int pubKeyDERLen = i2d_PUBKEY(this->dhKeyPair, &pubKeyDER);
    if (pubKeyDERLen <= 0)
    {
      logger_->log("Failed to serialize client's DH public key to DER format.");
      if (pubKeyDER)
        OPENSSL_free(pubKeyDER);
      return StatusCode::Error;
    }

    // Prepare the serialized data to include the client's DH public key
    std::vector<uint8_t> serialized_data;
    serialized_data.push_back(HS_CLIENT_KEY_EXCHANGE); // Prepend the message type
    // Append the DER-encoded public key
    serialized_data.insert(serialized_data.end(), pubKeyDER, pubKeyDER + pubKeyDERLen);

    // Free the DER-encoded public key memory
    OPENSSL_free(pubKeyDER);

    // create record
    Record record;
    record.hdr.record_type = REC_HANDSHAKE;
    record.hdr.tls_version = sslSharedInfo.chosen_tls_version_; // Assuming TLS version is globally defined
    record.hdr.data_size = serialized_data.size();
    record.data = new char[record.hdr.data_size];
    std::memcpy(record.data, serialized_data.data(), record.hdr.data_size);

    // Send the record
    StatusCode status = Ssl::socket_send_record(record, nullptr);
    if (status != StatusCode::Success)
    {
      logger_->log("SslClient:sendKeyExchange: Failed to send DHE Key Exchange.");
      return status;
    }
  }
  else if (this->sslSharedInfo.chosen_cipher_suite_ == TLS_RSA_WITH_AES_128_CBC_SHA_256)
  {
    // Example for TLS 1.2
    // First two bytes are the version number, followed by 46 random bytes
    const size_t pre_master_secret_length = 48;
    std::vector<uint8_t> pre_master_secret(pre_master_secret_length);

    // Set the first two bytes to the TLS version (for TLS 1.2, 0x0303)
    pre_master_secret[0] = 0x03;
    pre_master_secret[1] = 0x03;

    // Generate 46 random bytes for the rest of the pre-master secret
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 2; i < pre_master_secret_length; ++i)
    {
      pre_master_secret[i] = dis(gen);
    }

    // Store the generated pre-master secret
    this->sslSharedInfo.pre_master_secret_ = pre_master_secret;

    // RSA Key Exchange: Encrypt pre-master secret with server's public RSA key and send
    EVP_PKEY *pubkey = X509_get_pubkey(this->sslSharedInfo.server_certificate_);
    if (!pubkey)
    {
      logger_->log("SslClient:sendKeyExchange: Failed to get public key from server certificate.");
      return StatusCode::Error;
    }

    // Create a context for the encryption operation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0)
    {
      logger_->log("SslClient:sendKeyExchange: Encryption context initialization failed.");
      EVP_PKEY_free(pubkey);
      if (ctx)
        EVP_PKEY_CTX_free(ctx);
      return StatusCode::Error;
    }

    // Determine buffer size for encrypted pre-master secret
    size_t encryptedPreMasterSecretLen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &encryptedPreMasterSecretLen, this->sslSharedInfo.pre_master_secret_.data(), this->sslSharedInfo.pre_master_secret_.size()) <= 0)
    {
      logger_->log("SslClient:sendKeyExchange: Failed to determine buffer size for encrypted pre-master secret.");
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pubkey);
      return StatusCode::Error;
    }

    std::vector<unsigned char> encryptedPreMasterSecret(encryptedPreMasterSecretLen);
    if (EVP_PKEY_encrypt(ctx, encryptedPreMasterSecret.data(), &encryptedPreMasterSecretLen, this->sslSharedInfo.pre_master_secret_.data(), this->sslSharedInfo.pre_master_secret_.size()) <= 0)
    {
      logger_->log("SslClient:sendKeyExchange: Encryption of pre-master secret failed.");
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pubkey);
      return StatusCode::Error;
    }

    // Create the key exchange record for RSA
    std::vector<uint8_t> serialized_data;
    serialized_data.push_back(HS_CLIENT_KEY_EXCHANGE);
    serialized_data.insert(serialized_data.end(), encryptedPreMasterSecret.begin(), encryptedPreMasterSecret.end());

    // create record
    Record record;
    record.hdr.record_type = REC_HANDSHAKE;
    record.hdr.tls_version = sslSharedInfo.chosen_tls_version_; // Assuming TLS version is globally defined
    record.hdr.data_size = serialized_data.size();
    record.data = new char[record.hdr.data_size];
    std::memcpy(record.data, serialized_data.data(), record.hdr.data_size);

    // Send the record
    StatusCode status = Ssl::socket_send_record(record, nullptr);
    if (status != StatusCode::Success)
    {
      logger_->log("SslClient:sendKeyExchange: Failed to send RSA Key Exchange.");
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(pubkey);
      return status;
    }
    logger_->log("SslClient:sendKeyExchange: RSA Key Exchange sent successfully.");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
  }

  return StatusCode::Success;
}

StatusCode SslClient::send_finished()
{
  // Simulate the generation of a verification code. In a real scenario, this would involve complex cryptographic operations.
  std::string verificationCode = "\xAB\xCD\xEF"; // Example mock verification code represented as a string

  // The verification code is supposed to be encrypted with session keys. Here, we're using the updated aes_encrypt function.
  std::string encryptedVerificationCode; // Will hold the encrypted verification code
  if (aes_encrypt(verificationCode, sslSharedInfo.client_write_key_, sslSharedInfo.client_write_Iv_, encryptedVerificationCode) != true)
  {
    logger_->log("SSLClient:sendFinished: Encryption of verification code failed.");
    return StatusCode::Error;
  }

  // Create the Finished message
  std::vector<uint8_t> finishedMessage;
  finishedMessage.push_back(HS_FINISHED); // Message type for 'Finished'
  // Convert encryptedVerificationCode string to vector<uint8_t> and append
  finishedMessage.insert(finishedMessage.end(), encryptedVerificationCode.begin(), encryptedVerificationCode.end());

  // Create record
  Record record;
  record.hdr.record_type = REC_HANDSHAKE;
  record.hdr.tls_version = sslSharedInfo.chosen_tls_version_; // Assuming TLS version is hardcoded or determined elsewhere
  record.hdr.data_size = finishedMessage.size();
  record.data = new char[record.hdr.data_size];
  std::memcpy(record.data, finishedMessage.data(), record.hdr.data_size);

  // Send the Finished message
  StatusCode status = socket_send_record(record, nullptr);
  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:sendFinished: Failed to send Finished message.");
    delete[] record.data; // Remember to free allocated memory on error
    return StatusCode::Error;
  }

  delete[] record.data; // Free the allocated memory
  return StatusCode::Success;
}

StatusCode SslClient::receive_finished()
{
  // 1. Receive the record
  Record recv_record;
  StatusCode status = Ssl::socket_recv_record(&recv_record, nullptr);
  if (status != StatusCode::Success)
  {
    logger_->log("SSLClient:receiveFinished: Failed to receive Finished message.");
    return StatusCode::Error;
  }

  // 2. Ensure it's a Finished message
  if (recv_record.hdr.record_type != REC_HANDSHAKE || recv_record.data[0] != HS_FINISHED)
  {
    logger_->log("SSLClient:receiveFinished: Incorrect message type.");
    return StatusCode::Error;
  }

  // Assuming the rest of the message is the encrypted verification code
  std::string encryptedVerificationCode(reinterpret_cast<char *>(recv_record.data + 1), recv_record.hdr.data_size - 1);

  // Decrypt the verification code using the client's session keys
  std::string decryptedVerificationCode;
  if (aes_decrypt(encryptedVerificationCode, sslSharedInfo.server_write_key_, sslSharedInfo.server_write_Iv_, decryptedVerificationCode) != true)
  {
    logger_->log("SSLClient:receiveFinished: Decryption failed.");
    return StatusCode::Error;
  }

  // Verify the decrypted verification code. This is a placeholder check.
  // In a real implementation, this would involve checking the hash of all previous handshake messages.
  std::string expectedVerificationCode = "\xAB\xCD\xEF"; // Mock expected verification code for demonstration
  if (decryptedVerificationCode != expectedVerificationCode)
  {
    logger_->log("SSLClient:receiveFinished: Verification code mismatch.");
    return StatusCode::Error;
  }
  return StatusCode::Success;
}

template <typename T>
void secureClearVector(std::vector<T> &vec)
{
  std::memset(vec.data(), 0, vec.size() * sizeof(T));
  vec.clear();
}
StatusCode SslClient::calculate_master_secret_and_session_keys(int i)
{
  if (sslSharedInfo.pre_master_secret_.empty())
  {
    logger_->log("Pre-master secret is not set.\n");
    return StatusCode::Error;
  }

  // Step 1: Combine client and server random values
  std::vector<uint8_t> seed(8);

  // sslSharedInfo.client_random_ = 2551341790;
  // sslSharedInfo.server_random_ = 2990845779;
  std::memcpy(&seed[0], &sslSharedInfo.client_random_, sizeof(sslSharedInfo.client_random_));
  std::memcpy(&seed[4], &sslSharedInfo.server_random_, sizeof(sslSharedInfo.server_random_));

  // Step 2: Simplified PRF for Master Secret (for learning, not secure)
  std::vector<uint8_t> master_secret = simplifiedPRF(sslSharedInfo.pre_master_secret_, seed, 64);

  sslSharedInfo.master_secret_ = master_secret;

  secureClearVector(sslSharedInfo.client_write_key_);
  secureClearVector(sslSharedInfo.server_write_key_);
  secureClearVector(sslSharedInfo.client_write_Iv_);
  secureClearVector(sslSharedInfo.server_write_Iv_);

      // Step 3: Derive session keys (simplified)
  sslSharedInfo.client_write_key_ = std::vector<uint8_t>(master_secret.begin(), master_secret.begin() + 16);
  sslSharedInfo.server_write_key_ = std::vector<uint8_t>(master_secret.begin() + 16, master_secret.begin() + 32);
  sslSharedInfo.client_write_Iv_ = std::vector<uint8_t>(master_secret.begin() + 32, master_secret.begin() + 48);
  sslSharedInfo.server_write_Iv_ = std::vector<uint8_t>(master_secret.begin() + 48, master_secret.begin() + 64);

  sslSharedInfo.client_write_Iv_ = {10, 6, 6, 113, 1, 141, 52, 207, 198, 214, 55, 139, 68, 181, 165, 195};
  sslSharedInfo.server_write_Iv_ = {192, 58, 88, 71, 98, 5, 19, 238, 169, 196, 31, 114, 227, 172, 186, 10};


if(i==1){
  logger_->log("Client write key (Hex): " + toHexString(sslSharedInfo.client_write_key_));
  logger_->log("Server write key (Hex): " + toHexString(sslSharedInfo.server_write_key_));
}
// logger_->log("SslClient:calculate_master_secret_and_session_keys: Successfully calculated new session keys.");
  
// logger_->log("\n");
// if (sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
// {
//   char *dh_p_hex = BN_bn2hex(sslSharedInfo.dh_p_);
//   char *dh_g_hex = BN_bn2hex(sslSharedInfo.dh_g_);
//   logger_->log("DH Parameter p (Hex): ");
//   logger_->log(dh_p_hex ? dh_p_hex : "null");
//   logger_->log("DH Parameter g (Hex): ");
//   logger_->log(dh_g_hex ? dh_g_hex : "null");

//   // Free the allocated hex strings to prevent memory leaks
//   if (dh_p_hex)
//     OPENSSL_free(dh_p_hex);
//   if (dh_g_hex)
//     OPENSSL_free(dh_g_hex);
// }

// // Pre-master secret is binary data; for logging, convert it to hex or base64
// std::string pre_master_secret_hex;
// for (uint8_t byte : sslSharedInfo.pre_master_secret_)
// {
//   char buf[3];
//   snprintf(buf, sizeof(buf), "%02x", byte);
//   pre_master_secret_hex += buf;
// }
// logger_->log("Pre-Master Secret (Hex): " + pre_master_secret_hex);

// logger_->log("Client write key (Hex): " + toHexString(sslSharedInfo.client_write_key_));
// logger_->log("Server write key (Hex): " + toHexString(sslSharedInfo.server_write_key_));

StatusCode::Success;
}

StatusCode SslClient::handshake()
{
  logger_->log("Handshake begins.\n");

  // 1. sending ClientHello
  StatusCode status = this->send_hello();
  if (status == StatusCode::Error)
  {
    logger_->log("SslClient:handshake:Error in sending clientHello.");
    return status;
  }
  logger_->log("SslClient:handshake: Successfully sent ClientHello message.");

  // 2. receiving serverHello
  status = this->receive_hello(); // waiting for serverHello
  if (status == StatusCode::Error)
  {
    logger_->log("SslClient:handshake:Error in receiving serverHello.");
    return status;
  }
  logger_->log("SslClient:handshake: Successfully received ServerHello message.");

  // 3. receiving certificate
  status = this->receive_certificate(); // waiting for serverHello
  if (status == StatusCode::Error)
    return status;

  logger_->log("SslClient:handshake: Successfully received and verified Server's certificate.");

  // 4. receiving key exchange
  if (sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    status = this->receive_key_exchange(); // waiting for serverHello
    if (status == StatusCode::Error)
      return status;
    logger_->log("SslClient:handshake: Successfully received DHE Key Exchange message.");
  }

  // 5. receiving hello done
  status = this->receive_hello_done(); // waiting for serverHello
  if (status == StatusCode::Error)
    return status;

  logger_->log("SslClient:handshake: Successfully received Server HelloDone message.");

  // 6. sending key exchange
  status = this->send_key_exchange();
  if (status == StatusCode::Error)
    return status;
  if (sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    logger_->log("SslClient:handshake: Successfully sent DHE Key Exchange message.");
  }
  else
  {
    logger_->log("SslClient:handshake: Successfully sent RSA Key Exchange message.");
  }

  // 7. calculating master and session keys
  status = this->calculate_master_secret_and_session_keys(0);
  if (status == StatusCode::Error)
    return status;
  logger_->log("SslClient:handshake: Successfully calculated Master Secret and Session keys.");

  // 8. sending finished
  status = this->send_finished();
  if (status == StatusCode::Error)
    return status;

  logger_->log("SslClient:handshake: Successfully sent Finsihed message.");

  // 9. receiving finished
  status = this->receive_finished();
  if (status == StatusCode::Error)
    return status;

  logger_->log("SslClient:handshake: Successfully received and verified Finished message.");

  return StatusCode::Success;
}

StatusCode SslClient::send_refresh_key_request()
{
  // Create the key refresh request message
  std::vector<uint8_t> requestMessage;
  requestMessage.push_back(HS_KEYS_REFRESH); // Message type for keys refresh request message

  // Create record
  Record record;
  record.hdr.record_type = REC_HANDSHAKE;
  record.hdr.tls_version = sslSharedInfo.chosen_tls_version_; // Assuming TLS version is hardcoded or determined elsewhere
  record.hdr.data_size = requestMessage.size();
  record.data = new char[record.hdr.data_size];
  std::memcpy(record.data, requestMessage.data(), record.hdr.data_size);

  // Send the Finished message
  StatusCode status = socket_send_record(record, nullptr);
  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:send_key_refresh_request: Failed to send the keys refresh request message.");
    delete[] record.data; // Remember to free allocated memory on error
    return StatusCode::Error;
  }

  delete[] record.data; // Free the allocated memory
  logger_->log("\n");
  logger_->log("SslClient:send_key_refresh_request: Keys refresh request message sent successfully.");
  return StatusCode::Success;
}
StatusCode SslClient::receive_refresh_key_exchange()
{
  // 1. Receive the record
  Record recv_record;

  StatusCode status = this->socket_recv_record(&recv_record, nullptr);
  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Failed to receive Key Exchange data.");
    return StatusCode::Error;
  }

  // 2. Ensure it's a key exchange record
  if (recv_record.hdr.record_type != REC_HANDSHAKE)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Received record is not a Key Exchange message.");
    return StatusCode::Error;
  }

  uint8_t handshake_message_type = recv_record.data[0];
  if (handshake_message_type != HS_KEYS_REFRESH)
  {
    logger_->log("SSLClient:receive_refresh_key_exchange: Incorrect handshake message type.");
    return StatusCode::Error;
  }

  // Deserialize DHE parameters and server's public key from data
  const unsigned char *dataPtr1 = reinterpret_cast<const unsigned char *>(recv_record.data + 1); // Skipping message type                       // Adjusting for handshake message type
  size_t offset = 0;

  // Deserialize p, g, and server's public key from data
  std::vector<uint8_t> p_vec = readLengthPrefixedVector(dataPtr1, offset);
  std::vector<uint8_t> g_vec = readLengthPrefixedVector(dataPtr1, offset);
  std::vector<uint8_t> server_pub_key_der = readLengthPrefixedVector(dataPtr1, offset);

  // clear_ssl_shared_info(this->sslSharedInfo);
  // Deserialize the server's public key from DER format
  EVP_PKEY *server_pub_key = nullptr;
  const unsigned char *pubKeyPtr1 = server_pub_key_der.data();
  server_pub_key = d2i_PUBKEY(nullptr, &pubKeyPtr1, server_pub_key_der.size());
  if (!server_pub_key)
  {
    // If deserialization of the server's public key fails
    logger_->log("SslClient:receive_refresh_key_exchange: Failed to deserialize server's public DH key. Data size: " + std::to_string(server_pub_key_der.size()));
    return StatusCode::Error;
  }

  // Convert vectors back to BIGNUM*
  BIGNUM *p = vector_to_BIGNUM(p_vec);
  BIGNUM *g = vector_to_BIGNUM(g_vec);

  // Convert BIGNUMs to OSSL_PARAM
  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
  OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

  // Set DH parameters
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
  if (EVP_PKEY_fromdata_init(pctx) <= 0)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Failed to initialize DH parameters.");
    // Cleanup
  }

  EVP_PKEY *param_key = NULL;
  if (EVP_PKEY_fromdata(pctx, &param_key, EVP_PKEY_KEY_PARAMETERS, params) <= 0)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Failed to set DH parameters.");
    // Cleanup
  }

  // Generate the client's DH key pair
  EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
  if (EVP_PKEY_keygen_init(keygen_ctx) <= 0 ||
      EVP_PKEY_keygen(keygen_ctx, &this->dhKeyPair) <= 0)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Failed to generate client's DH key pair.");
    // Cleanup
  }

  // Setup the context for deriving the shared secret
  EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(this->dhKeyPair, nullptr); // Use client's DH key pair
  if (!derive_ctx)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Failed to create context for deriving shared secret.");
    EVP_PKEY_free(this->dhKeyPair); // Assuming dhKeyPair is the client's key pair
    EVP_PKEY_free(server_pub_key);  // Free server's public key
    return StatusCode::Error;
  }

  if (EVP_PKEY_derive_init(derive_ctx) <= 0)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Failed to initialize shared secret derivation.");
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(this->dhKeyPair);
    EVP_PKEY_free(server_pub_key);
    return StatusCode::Error;
  }

  // Set the peer's public key (server's public key) for the derivation process
  if (EVP_PKEY_derive_set_peer(derive_ctx, server_pub_key) <= 0)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Failed to set the server's public key for shared secret derivation.");
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(this->dhKeyPair);
    EVP_PKEY_free(server_pub_key);
    return StatusCode::Error;
  }

  // Determine buffer length for the shared secret
  size_t secret_len = 0;
  if (EVP_PKEY_derive(derive_ctx, nullptr, &secret_len) <= 0)
  {
    logger_->log("Failed to determine the length of the shared secret.");
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(this->dhKeyPair);
    EVP_PKEY_free(server_pub_key);
    return StatusCode::Error;
  }

  // Allocate the buffer and derive the shared secret
  std::vector<unsigned char> shared_secret(secret_len);

  if (EVP_PKEY_derive(derive_ctx, shared_secret.data(), &secret_len) <= 0)
  {
    logger_->log("SslClient:receive_refresh_key_exchange: Shared secret derivation failed.");
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(this->dhKeyPair);
    EVP_PKEY_free(server_pub_key);
    return StatusCode::Error;
  }

  // Store the shared secret
  sslSharedInfo.pre_master_secret_.assign(shared_secret.begin(), shared_secret.end());
  sslSharedInfo.dh_p_ = BN_dup(p); // store p
  sslSharedInfo.dh_g_ = BN_dup(g);
  // dh key pair already stored

  EVP_PKEY_CTX_free(derive_ctx);
  EVP_PKEY_free(server_pub_key);
  logger_->log("SslClient:receive_refresh_key_exchange: Successfully received DHE key exchange.");
  return StatusCode::Success;
}
StatusCode SslClient::send_refresh_key_exchange()
{
  if (this->sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    // Serialize the public key of the client's DH key pair to DER format
    unsigned char *pubKeyDER = nullptr; // Pointer to DER encoded public key
    int pubKeyDERLen = i2d_PUBKEY(this->dhKeyPair, &pubKeyDER);
    if (pubKeyDERLen <= 0)
    {
      logger_->log("SslClient:send_refresh_key_exchange: Failed to serialize client's DH public key to DER format.");
      if (pubKeyDER)
        OPENSSL_free(pubKeyDER);
      return StatusCode::Error;
    }

    // Prepare the serialized data to include the client's DH public key
    std::vector<uint8_t> serialized_data;
    serialized_data.push_back(HS_KEYS_REFRESH); // Prepend the message type
    // Append the DER-encoded public key
    serialized_data.insert(serialized_data.end(), pubKeyDER, pubKeyDER + pubKeyDERLen);

    // Free the DER-encoded public key memory
    OPENSSL_free(pubKeyDER);

    // create record
    Record record;
    record.hdr.record_type = REC_HANDSHAKE;
    record.hdr.tls_version = sslSharedInfo.chosen_tls_version_; // Assuming TLS version is globally defined
    record.hdr.data_size = serialized_data.size();
    record.data = new char[record.hdr.data_size];
    std::memcpy(record.data, serialized_data.data(), record.hdr.data_size);

    // Send the record
    StatusCode status = Ssl::socket_send_record(record, nullptr);
    if (status != StatusCode::Success)
    {
      logger_->log("SslClient:send_refresh_key_exchange: Failed to send DHE Key Exchange.");
      return status;
    }
  }

  logger_->log("SslClient:send_refresh_key_exchange: Successfully sent DHE Key Exchange.");
  logger_->log("\n");
  return StatusCode::Success;
}



void SslClient::clear_ssl_shared_info(SSLSharedInfo &sslSharedInfo)
{
  // // Free the server certificate if it exists
  // if (sslSharedInfo.server_certificate_)
  // {
  //   X509_free(sslSharedInfo.server_certificate_);
  //   sslSharedInfo.server_certificate_ = nullptr;
  // }

  // // Free the DH parameters if they exist
  // if (sslSharedInfo.dh_p_)
  // {
  //   BN_free(sslSharedInfo.dh_p_);
  //   sslSharedInfo.dh_p_ = nullptr;
  // }
  // if (sslSharedInfo.dh_g_)
  // {
  //   BN_free(sslSharedInfo.dh_g_);
  //   sslSharedInfo.dh_g_ = nullptr;
  // }

  // Securely clear vectors containing sensitive information
  secureClearVector(sslSharedInfo.pre_master_secret_);
  secureClearVector(sslSharedInfo.master_secret_);
  secureClearVector(sslSharedInfo.client_write_key_);
  secureClearVector(sslSharedInfo.server_write_key_);
  secureClearVector(sslSharedInfo.client_write_Iv_);
  secureClearVector(sslSharedInfo.server_write_Iv_);

  this->dhKeyPair = nullptr;

  // Reset other fields as necessary
  // sslSharedInfo.client_id_ = 0;
  // sslSharedInfo.chosen_tls_version_ = 0;
  // sslSharedInfo.chosen_cipher_suite_ = 0;
  // sslSharedInfo.client_random_ = 0;
  // sslSharedInfo.server_random_ = 0;
}

bool SslClient::handle_dhe()
{

  StatusCode status = send_refresh_key_request();
  status = receive_refresh_key_exchange();
  status = send_refresh_key_exchange();
  status = calculate_master_secret_and_session_keys(1);


  return true;

}

StatusCode SslClient::socket_connect(const std::string &server_ip, int server_port, string key_exchange_algorithm)
{
  // Here's the typical flow:

  //     Establish a TCP connection.
  //     Perform the SSL/TLS handshake to securely negotiate encryption keys and cipher suites.
  //     Once the handshake is complete, proceed with secure data transmission.

  logger_->log("SslClient:socket_connect: Attempting to establish a TCP connection with the server.");
  if (this->tcp_->socket_connect(server_ip, server_port) != StatusCode::Success)
  {
    logger_->log("SslClient:socket_connect:Error in establishing a TCP connection with the server.");
    return StatusCode::Error;
  }

  logger_->log("SslClient:socket_connect: Successful in establishing a TCP connection with the server.");
  if (key_exchange_algorithm == "DHE")
  {
    this->supported_cipher_suites.push_back(TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256);
  }
  else if (key_exchange_algorithm == "RSA")
  {
    this->supported_cipher_suites.push_back(TLS_RSA_WITH_AES_128_CBC_SHA_256);
  }
  // IMPLEMENT HANDSHAKE HERE

  StatusCode status = handshake();

  if (status != StatusCode::Success)
  {
    logger_->log("SslClient::socket_connect:Failed in performing the handshake.");
    this->tcp_->socket_close(); // close the TCP
    this->tcp_->logger_ = nullptr;
    delete[] this->tcp_;
    this->tcp_ = nullptr;

    return StatusCode::Error;
  }

  logger_->log("SslClient:socket_connect: Successful in establishing an SSL connection with the server.\n");

  // Assuming logger_ is accessible and SSLSharedInfo instance is named sslSharedInfo for both server and client
  logger_->log("SSL Shared Data:\n");
  logger_->log("Chosen TLS version: ");
  logger_->log(std::to_string(sslSharedInfo.chosen_tls_version_));
  logger_->log("Chosen Cipher Suite: ");
  logger_->log(std::to_string(sslSharedInfo.chosen_cipher_suite_));
  logger_->log("Client Random: ");
  logger_->log(std::to_string(sslSharedInfo.client_random_));
  logger_->log("Server Random: ");
  logger_->log(std::to_string(sslSharedInfo.server_random_));

  // For BIGNUM values, you will need to convert them to a readable format

  if (sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    char *dh_p_hex = BN_bn2hex(sslSharedInfo.dh_p_);
    char *dh_g_hex = BN_bn2hex(sslSharedInfo.dh_g_);
    logger_->log("DH Parameter p (Hex): ");
    logger_->log(dh_p_hex ? dh_p_hex : "null");
    logger_->log("DH Parameter g (Hex): ");
    logger_->log(dh_g_hex ? dh_g_hex : "null");
  }

  // Pre-master secret is binary data; for logging, convert it to hex or base64
  std::string pre_master_secret_hex;
  for (uint8_t byte : sslSharedInfo.pre_master_secret_)
  {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", byte);
    pre_master_secret_hex += buf;
  }
  logger_->log("Pre-Master Secret (Hex): " + pre_master_secret_hex);

  logger_->log("client write key size: ");
  logger_->log(std::to_string(sslSharedInfo.client_write_Iv_.size()));

  logger_->log("server write key size: ");
  logger_->log(std::to_string(sslSharedInfo.server_write_Iv_.size()));

  logger_->log("Client write key (Hex): " + toHexString(sslSharedInfo.client_write_key_));
  logger_->log("Server write key (Hex): " + toHexString(sslSharedInfo.server_write_key_));

  // logger_->log("client write iv (Hex): " + toHexString(sslSharedInfo.client_write_Iv_));
  // logger_->log("server write iv (Hex): " + toHexString(sslSharedInfo.server_write_Iv_));

  return StatusCode::Success;
}

StatusCode SslClient::socket_send_string(const std::string &send_string, TCP *tcpInstance)
{ // sends the given string of daa over the TCP connection

  StatusCode status;

  if (tcpInstance == nullptr)
  {
    status = Ssl::socket_send_string(send_string, sslSharedInfo.client_write_key_, sslSharedInfo.client_write_Iv_, nullptr);
  }
  else
  {

    status = Ssl::socket_send_string(send_string, sslSharedInfo.server_write_key_, sslSharedInfo.server_write_Iv_, tcpInstance);
  }

  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:socket_send_string:Failed in sending the message.");
  }
  else
  {
    logger_->log("\n");
    logger_->log("SslClient:socket_send_string: Successful in sending the message: " + send_string);
    logger_->log("SslClient:socket_send_string: Current Session keys: ");

    logger_->log("Client write key (Hex): " + toHexString(sslSharedInfo.client_write_key_));
    logger_->log("Server write key (Hex): " + toHexString(sslSharedInfo.server_write_key_));

    // logger_->log("client write iv (Hex): " + toHexString(sslSharedInfo.client_write_Iv_));
    // logger_->log("server write iv (Hex): " + toHexString(sslSharedInfo.server_write_Iv_));
  }

  if (this->sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    // handle_dhe();
  }

  return status;
}
StatusCode SslClient::socket_recv_string(std::string *recv_string, TCP *tcpInstance) // sends the given string of daa over the TCP connection
{

  StatusCode status;

  if (tcpInstance == nullptr)
  {
    status = Ssl::socket_recv_string(recv_string, sslSharedInfo.server_write_key_, sslSharedInfo.server_write_Iv_, nullptr);
    logger_->log("\n");
    logger_->log("SslClient:socket_recv_string: Successful in receiving the message: " + *recv_string);
    logger_->log("SslClient:socket_recv_string: Current Session keys: ");

    logger_->log("Client write key (Hex): " + toHexString(sslSharedInfo.client_write_key_));
    logger_->log("Server write key (Hex): " + toHexString(sslSharedInfo.server_write_key_));

    // logger_->log("client write iv (Hex): " + toHexString(sslSharedInfo.client_write_Iv_));
    // logger_->log("server write iv (Hex): " + toHexString(sslSharedInfo.server_write_Iv_));
  }
  else
  {
    status = Ssl::socket_recv_string(recv_string, SslClient::sslSharedInfo.client_write_key_, SslClient::sslSharedInfo.client_write_Iv_, tcpInstance);
    SslServer::logger_->log("\n");
    SslServer::logger_->log("SslClient:socket_recv_string: Successful in receiving the message: " + *recv_string);
    SslServer::logger_->log("SslClient:socket_recv_string: Current Session keys: ");

    SslServer::logger_->log("Client write key (Hex): " + toHexString(sslSharedInfo.client_write_key_));
    SslServer::logger_->log("Server write key (Hex): " + toHexString(sslSharedInfo.server_write_key_));
    // SslServer::logger_->log("client write iv (Hex): " + toHexString(sslSharedInfo.client_write_Iv_));
    // SslServer::logger_->log("server write iv (Hex): " + toHexString(sslSharedInfo.server_write_Iv_));
  }

  if (status != StatusCode::Success)
  {
    logger_->log("SslClient:socket_send:Failed in sending the message.");
  }
  else
  {
  }

  if (this->sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    // handle_dhe();
  }
  return status;
}