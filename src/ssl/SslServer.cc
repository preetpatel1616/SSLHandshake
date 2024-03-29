#include "SslServer.h"
#include "crypto_adaptor.h"
#include "SslClient.h"
#include "../common/Logger/Logger.h"
#include "../common/Utils/Utils.h"

#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <string>
#include <cstring>

#include <iostream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/err.h>

using namespace std;

SslServer::SslServer(const std::string &certificate_path, const std::string &key_path)
{ // 1. initializes the server, sets up logging, and flags the server as open
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0)
  {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_server_" + datetime + ".log"));
  this->logger_->log("SslServer:constructor: SslServer object created. Server Log at " + datetime + "\n");

  // this->tcp_->logger_ = this->logger_;
  this->closed_ = false;
  this->client_id_ = 1;

  // Initialize with supported versions
  supported_tls_versions_.insert(TLS_1_0); // TLS 1.0
  supported_tls_versions_.insert(TLS_1_1); // TLS 1.1
  supported_tls_versions_.insert(TLS_1_2); // TLS 1.2

  // Initialize OpenSSL
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  // Create a new SSL_CTX object as a framework to establish TLS/SSL enabled connections
  const SSL_METHOD *method = TLS_server_method();
  sslCtx_ = SSL_CTX_new(method);
  if (!sslCtx_)
  {
    // Log and handle error
    this->logger_->log("SslServer:constructor: Failed to create SSL_CTX");
    exit(1);
  }

  // Load the server's certificate and corresponding private key
  if (SSL_CTX_use_certificate_file(sslCtx_, certificate_path.c_str(), SSL_FILETYPE_PEM) <= 0)
  {
    this->logger_->log("SslServer:constructor: Failed to load certificate");

    SSL_CTX_free(sslCtx_);
    exit(1);
  }

  if (SSL_CTX_use_PrivateKey_file(sslCtx_, key_path.c_str(), SSL_FILETYPE_PEM) <= 0)
  {
    this->logger_->log("SslServer:constructor: Failed to load private key");

    SSL_CTX_free(sslCtx_);
    exit(1);
  }

  // Verify that the private key matches the certificate
  if (!SSL_CTX_check_private_key(sslCtx_))
  {
    this->logger_->log("SslServer:constructor: Private key does not match the public certificate");

    SSL_CTX_free(sslCtx_);
    exit(1);
  }
}

SslServer::~SslServer()
{

  // Clean up the SSL context
  if (sslCtx_ != nullptr)
  {
    SSL_CTX_free(sslCtx_);
  }
  // Destructor
  if (!this->closed_)
  { // Closes any active connections
    this->shutdown();
  }
  if (this->logger_) // checking if the logger is a nullptr
  {                  // Deletes the logger object and sets the logger pointer to NULL
    this->logger_->log("SslServer:deconstructor:SslServer object is being destroyed.\n");
    delete this->logger_;
    this->logger_ = nullptr;       // setting the logger pointer to null after it is being deleted
    this->tcp_->logger_ = nullptr; // assigning the SSL's associated TCP object's logger to nullptr ass well
  }
}

bool SslServer::server_supports(uint16_t tls_version)
{

  return this->supported_tls_versions_.find(tls_version) != supported_tls_versions_.end();
}

StatusCode SslServer::receive_hello(int client_id, SSLSharedInfo &sslSharedInfo)
{ // Server waits to receive a clientHello message
  if (this->closed_)
  {
    logger_->log("SslServer:receiveHello: Server is closed, cannot accept new connections.");
    return StatusCode::Error;
  }

  // 1. receive record
  Record recv_record;

  StatusCode status = this->socket_recv_record(&recv_record, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:receive_hello: Failed to receive record.");
    return StatusCode::Error;
  }

  if (recv_record.hdr.record_type != REC_HANDSHAKE)
  {
    logger_->log("SslClient:receiveHello: Received record is not a handshake message.");
    return StatusCode::Error;
  }

  // 2. deserialize the record.data into clientHello instance
  ClientHello clientHello;
  size_t index = 0;

  // deserialize the handhsake message type first and process it
  uint8_t handshake_message_type = static_cast<uint8_t>(recv_record.data[index]);
  if (handshake_message_type != HS_CLIENT_HELLO)
  {
    logger_->log("SslServer:receiveHello: The received handshake record is not client hello.");
    return StatusCode::Error;
  }
  index += sizeof(handshake_message_type);

  // 2.1 deserialize tls version
  clientHello.tls_negotiate_version_ = static_cast<uint16_t>(recv_record.data[index] << 8) | (recv_record.data[index + 1]);
  index += sizeof(clientHello.tls_negotiate_version_);
  // 2.2 deserialize random
  clientHello.random_ = 0;
  for (int i = 0; i < 4; ++i)
  {
    clientHello.random_ |= static_cast<uint32_t>(recv_record.data[index + i]) << ((3 - i) * 8);
  }
  index += sizeof(clientHello.random_);

  // 2.3 deserialize ciphersuites
  while (index + 1 < recv_record.hdr.data_size)
  {
    uint16_t cipherSuite = static_cast<uint16_t>(recv_record.data[index] << 8) | recv_record.data[index + 1];
    clientHello.cipher_suites_.push_back(cipherSuite);
    index += sizeof(cipherSuite);
  }

  // logger_->log("SslServer:receive_hello: ClientHello Data\n");
  // logger_->log("\nSslServer:receive_hello: Supported tls version: ");
  // logger_->log(std::to_string(clientHello.tls_negotiate_version_));
  // logger_->log("SslServer:receive_hello: TLS 1_2: ");
  // logger_->log(std::to_string(TLS_1_2));
  // logger_->log("SslServer:receive_hello: Client random: ");
  // logger_->log(std::to_string(clientHello.random_));
  // logger_->log("SslServer:receive_hello: Supported cipher suites: ");
  // std::string myString(clientHello.cipher_suites_.begin(), clientHello.cipher_suites_.end());
  // logger_->log(myString);

  // 3. process clientHello message
  uint16_t chosen_tls_version;

  // 3.1 process tls version
  if (clientHello.tls_negotiate_version_ >= TLS_1_2 && server_supports(TLS_1_2))
  {
    chosen_tls_version = TLS_1_2;
  }
  else if (clientHello.tls_negotiate_version_ >= TLS_1_1 && server_supports(TLS_1_1))
  {
    chosen_tls_version = TLS_1_1;
  }
  else if (clientHello.tls_negotiate_version_ >= TLS_1_0 && server_supports(TLS_1_0))
  {
    chosen_tls_version = TLS_1_0;
  }
  else
  {
    // Log and handle error: No common TLS version found.
    logger_->log("SslServer:sendHello: No compatible TLS version found with the client.");
    return StatusCode::Error;
  }

  // 3.2 process cipher suites
  bool isDhe = false;
  bool isRsa = false;

  if (clientHello.cipher_suites_[0] == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    isDhe = true;
  }
  else if (clientHello.cipher_suites_[0] == TLS_RSA_WITH_AES_128_CBC_SHA_256)
  {
    isRsa = true;
  }

  // assigning values to sslSharedInfo

  sslSharedInfo.chosen_tls_version_ = chosen_tls_version;
  sslSharedInfo.client_random_ = clientHello.random_;

  if (isDhe)
  {
    // Proceed with DHE key exchange
    logger_->log("SslServer:receiveHello: Proceeding with DHE key exchange.");
    send_hello(client_id, "DHE", sslSharedInfo);
  }
  else if (isRsa)
  {
    // Proceed with RSA key exchange
    logger_->log("SslServer:receiveHello: Proceeding with RSA key exchange.");
    send_hello(client_id, "RSA", sslSharedInfo);
  }
  else
  {
    logger_->log("SslServer:receiveHello: No compatible cipher suite found.");
    return StatusCode::Error;
  }

  logger_->log("SslServer:receiveHello: ClientHello message received and processed successfully.");
  delete[] recv_record.data;
  recv_record.data = nullptr;
  return StatusCode::Success;
}
StatusCode SslServer::send_hello(int client_id, const std::string key_exchange_algorithm, SSLSharedInfo &sslSharedInfo)
{
  if (this->closed_)
  {
    logger_->log("SslServer:sendHello: Server is closed, cannot send Hello.");
    return StatusCode::Error;
  }
  // Construct ServerHello
  ServerHello serverHello;
  serverHello.chosen_tls_version_ = sslSharedInfo.chosen_tls_version_;
  // serverHello.random_ = generate_random_uint32(); // Implement this function to generate a random number
  serverHello.random_ = 0x87654321;
  if (key_exchange_algorithm == "DHE")
  {
    serverHello.chosen_cipher_suite_ = TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256;
  }
  else if (key_exchange_algorithm == "RSA")
  {
    serverHello.chosen_cipher_suite_ = TLS_RSA_WITH_AES_128_CBC_SHA_256;
  }
  else
  {
    logger_->log("SslServer:sendHello: No compatible cipher suite found.");
    return StatusCode::Error;
  }

  // logger_->log("SslServer:send_hello: ServerHello Data\n");
  // logger_->log("\nSslServer:send_hello: Chosen tls version: ");
  // logger_->log(std::to_string(serverHello.chosen_tls_version_));
  // logger_->log("SslServer:send_hello: TLS 1_2: ");
  // logger_->log(std::to_string(TLS_1_2));
  // logger_->log("SslServer:send_hello: Server random: ");
  // logger_->log(std::to_string(serverHello.random_));
  // logger_->log("SslServer:send_hello: Chosen cipher suites: ");
  // logger_->log(std::to_string(serverHello.chosen_cipher_suite_));

  // Calculate buffer size
  size_t buffer_size = 1; // For handshake message type
  buffer_size += 2;       // For version
  buffer_size += 4;       // For random
  buffer_size += 2;       // For cipher suite

  // Serialize ServerHello
  char *serializedServerHello = new char[buffer_size];
  size_t index = 0;

  // Handshake message type
  serializedServerHello[index++] = HS_SERVER_HELLO;

  // Version
  serializedServerHello[index++] = static_cast<char>(serverHello.chosen_tls_version_ >> 8);
  serializedServerHello[index++] = static_cast<char>(serverHello.chosen_tls_version_ & 0xFF);

  // Random
  for (int i = 3; i >= 0; --i)
  {
    serializedServerHello[index++] = (serverHello.random_ >> (i * 8)) & 0xFF;
  }

  // Cipher suite
  serializedServerHello[index++] = static_cast<char>(serverHello.chosen_cipher_suite_ >> 8);
  serializedServerHello[index++] = static_cast<char>(serverHello.chosen_cipher_suite_ & 0xFF);

  // 5. Create the ServerHello record
  Record record;
  record.hdr.record_type = REC_HANDSHAKE;                     // Handshake record
  record.hdr.tls_version = sslSharedInfo.chosen_tls_version_; // Protocol version
  record.hdr.data_size = static_cast<uint16_t>(buffer_size);
  record.data = serializedServerHello;

  // send the serverhello record
  StatusCode status = this->socket_send_record(record, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:sendHello: Failed to send ServerHello message.");
    delete[] record.data; // Free dynamically allocated memory to avoid leaks
    record.data = nullptr;
    return StatusCode::Error;
  }

  sslSharedInfo.chosen_cipher_suite_ = serverHello.chosen_cipher_suite_;
  sslSharedInfo.server_random_ = serverHello.random_;

  logger_->log("SslServer:sendHello: ServerHello message sent successfully.");
  delete[] record.data; // Free dynamically allocated memory to avoid leaks
  return StatusCode::Success;
}
StatusCode SslServer::send_certificate(int client_id, SSLSharedInfo &sslSharedInfo)
{
  if (this->closed_)
  {
    logger_->log("SslServer:sendCertificate: Server is closed, cannot send certificate.");
    return StatusCode::Error;
  }

  // Ensure SSL context and session are properly initialized
  if (!sslCtx_)
  {
    this->logger_->log("SslServer:sendCertificate: SSL context not initialized.");
    return StatusCode::Error;
  }

  std::vector<uint8_t> serializedData;

  // Prepend the handshake message type
  serializedData.push_back(HS_CERTIFICATE);

  // Retrieve the certificate from the SSL context
  X509 *cert = SSL_CTX_get0_certificate(sslCtx_);
  if (!cert)
  {
    logger_->log("SslServer:sendCertificate:Failed to get certificate from SSL context.");
    return StatusCode::Error;
  }

  // Add the certificate to sslSharedInfo
  if (sslSharedInfo.server_certificate_)
  {
    X509_free(sslSharedInfo.server_certificate_); // Free existing certificate if present
  }
  sslSharedInfo.server_certificate_ = X509_dup(cert); // Duplicate and store the certificate

  // Serialize the certificate
  int len = i2d_X509(cert, nullptr); // Determine the length needed
  if (len < 0)
  {
    logger_->log("SslServer:sendCertificate:Error determining certificate length.");
    return StatusCode::Error;
  }

  // Allocate space for the certificate in the vector

  size_t startPos = serializedData.size();
  serializedData.resize(startPos + len);
  unsigned char *p = serializedData.data() + startPos;
  if (i2d_X509(cert, &p) < 0)
  {
    logger_->log("SslServer:sendCertificate:Error serializing certificate.");
    return StatusCode::Error;
  }

  // Create record
  Record record;

  record.hdr.record_type = REC_HANDSHAKE;
  record.hdr.tls_version = TLS_1_2; // assign the chosen_tls_verion between you and clients
  record.hdr.data_size = static_cast<uint16_t>(serializedData.size());
  record.data = new char[record.hdr.data_size]; // Allocate memory for the record data

  // Copy the serialized certificate into the record data
  std::memcpy(record.data, serializedData.data(), serializedData.size());

  StatusCode status = Ssl::socket_send_record(record, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:sendCertificate: Failed to send certificate.");
    delete[] record.data;
    return StatusCode::Error;
  }

  logger_->log("SslServer:sendCertificate: Certificate sent successfully.");
  delete[] record.data;
  record.data = nullptr;
  return StatusCode::Success;
}
StatusCode SslServer::send_key_exchange(int client_id, SSLSharedInfo &sslSharedInfo, SSLServerSession &sslServerSession)
{
  if (this->closed_)
  {
    logger_->log("SslServer:sendKeyExchange: Server is closed, cannot send Key Exchange.");
    return StatusCode::Error;
  }
  if (sslSharedInfo.chosen_cipher_suite_ == TLS_RSA_WITH_AES_128_CBC_SHA_256)
  {
    // For RSA, since the certificate containing the RSA public key has been sent,
    // the server waits for the client to send an encrypted pre-master secret.
    logger_->log("SslServer:sendKeyExchange: RSA key exchange, awaiting encrypted pre-master secret from client.");
    return StatusCode::Success;
  }

  else if (sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    // Step 1: Generate DH parameters
    EVP_PKEY_CTX *paramgen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    if (!paramgen_ctx)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to create EVP_PKEY_CTX for parameters generation");
      return StatusCode::Error;
    }

    // generate dh parameters
    if (EVP_PKEY_paramgen_init(paramgen_ctx) <= 0)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to initialize parameter generation.");
      EVP_PKEY_CTX_free(paramgen_ctx);
      return StatusCode::Error;
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(paramgen_ctx, 512) <= 0)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to set DH parameter generation prime length.");
      EVP_PKEY_CTX_free(paramgen_ctx);
      return StatusCode::Error;
    }

    EVP_PKEY *params = nullptr;

    if (EVP_PKEY_paramgen(paramgen_ctx, &params) <= 0)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to generate parameters.");
      EVP_PKEY_CTX_free(paramgen_ctx);
      return StatusCode::Error;
    }
    // Free the parameter generation context
    EVP_PKEY_CTX_free(paramgen_ctx);

    // Generate dh key pair
    EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new(params, nullptr);
    if (!keygen_ctx)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to create EVP_PKEY_CTX for key generation");
      EVP_PKEY_free(params);
      return StatusCode::Error;
    }

    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to initialize or generate key pair");
      EVP_PKEY_CTX_free(keygen_ctx);
      EVP_PKEY_free(params);
      return StatusCode::Error;
    }

    if (EVP_PKEY_keygen(keygen_ctx, &this->dhKeyPair) <= 0)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to generate key pair.");
      EVP_PKEY_CTX_free(keygen_ctx);
      EVP_PKEY_free(params);
      return StatusCode::Error;
    }
    EVP_PKEY_CTX_free(keygen_ctx); // Key generation context no longer needed

    // Now you can access p, g, pub_key, and priv_key
    BIGNUM *p = NULL, *g = NULL;
    EVP_PKEY_get_bn_param(params, "p", &p);
    EVP_PKEY_get_bn_param(params, "g", &g);

    // Since DH_get0_* does not increase the reference count, duplicating BIGNUM* for safe memory management
    sslSharedInfo.dh_p_ = BN_dup(p);
    sslSharedInfo.dh_g_ = BN_dup(g);
    // already stored dhKeyPair

    // Serialize p, g, and public key
    std::vector<uint8_t> serializedData;
    serializedData.push_back(HS_SERVER_KEY_EXCHANGE);
    auto p_vec = BIGNUM_to_vector(sslSharedInfo.dh_p_);
    auto g_vec = BIGNUM_to_vector(sslSharedInfo.dh_g_);
    unsigned char *pubKeyData = nullptr;
    int pubKeyLen = i2d_PUBKEY(this->dhKeyPair, &pubKeyData);
    if (pubKeyLen <= 0)
    {
      logger_->log("Failed to serialize DH public key.");
      return StatusCode::Error;
    }

    // prepend length and append data for p,g and servers public key
    prependLength(serializedData, p_vec);
    prependLength(serializedData, g_vec);
    prependLength(serializedData, std::vector<uint8_t>(pubKeyData, pubKeyData + pubKeyLen));
    OPENSSL_free(pubKeyData); // Ensure to free the serialized data

    // // Logging for debugging purposes
    // logger_->log("p: " + toHexString(p_vec));
    // logger_->log("g: " + toHexString(g_vec));
    // logger_->log("server public key: " + toHexString(pub_key_vec));

    // Construct the record (simplified, adjust according to your Record structure)
    Record record;
    record.hdr.record_type = REC_HANDSHAKE;
    record.hdr.tls_version = sslSharedInfo.chosen_tls_version_;
    record.hdr.data_size = static_cast<uint16_t>(serializedData.size());
    record.data = new char[record.hdr.data_size];
    // Copy the serialized data into the record's data
    std::memcpy(record.data, serializedData.data(), serializedData.size());

    logger_->log("SslServer:sendKeyExchange: Before sending the record");

    // Send the record
    StatusCode status = this->socket_send_record(record, client_id_to_server_session_[client_id].tcpClient);
    logger_->log("Just after sending the record: " + std::to_string(bool(status)));
    if (status != StatusCode::Success)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to send DHE key exchange.");
      delete[] record.data;
      // EVP_PKEY_CTX_free(paramgen_ctx);
      // EVP_PKEY_CTX_free(keygen_ctx);
      // EVP_PKEY_free(params);
      return StatusCode::Error;
    }

    logger_->log("SslServer:sendKeyExchange: DHE key exchange sent successfully.");
    delete[] record.data; // Remember to free the allocated memory
    // EVP_PKEY_CTX_free(paramgen_ctx);
    // EVP_PKEY_CTX_free(keygen_ctx);
    // EVP_PKEY_free(params);
    logger_->log("About to return success in send key exchange");
    return StatusCode::Success;
  }
}

StatusCode SslServer::send_hello_done(int client_id, SSLSharedInfo &sslSharedInfo)
{
  if (this->closed_)
  {
    logger_->log("SslServer:sendHelloDone: Server is closed, cannot send HelloDone.");
    return StatusCode::Error;
  }

  // Construct the HelloDone message. Since ServerHelloDone has no payload, we only care about the message type.
  size_t bufferSize = sizeof(uint8_t); // Assuming HS_SERVER_HELLO_DONE is just a message type identifier

  // Allocate buffer for the message
  char *helloDoneMessage = new char[bufferSize];

  // Serialize the HelloDone message type directly into the buffer
  helloDoneMessage[0] = static_cast<char>(HS_SERVER_HELLO_DONE);

  // Construct the HelloDone message
  Record record;
  record.hdr.tls_version = sslSharedInfo.chosen_tls_version_; // Assuming TLS version has been negotiated
  record.hdr.record_type = REC_HANDSHAKE;                     // The record type for HelloDone
  record.hdr.data_size = static_cast<uint16_t>(bufferSize);   // Should be 0 or the size of the message if it had a payload;                     // HelloDone has no payload
  record.data = helloDoneMessage;                             // Dynamically allocate memory for the data;                       // No data for HelloDone
  // Send the HelloDone record
  StatusCode status = Ssl::socket_send_record(record, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:sendHelloDone: Failed to send HelloDone message.");
    return StatusCode::Error;
  }

  logger_->log("SslServer:sendHelloDone: HelloDone message sent successfully.");
  delete[] record.data;
  return StatusCode::Success;
}

StatusCode SslServer::receive_key_exchange(int client_id, SSLSharedInfo &sslSharedInfo, SSLServerSession &sslServerSession)
{
  if (this->closed_)
  {
    logger_->log("SslServer:receiveKeyExchange: Server is closed, cannot receive key exchange data.");
    return StatusCode::Error;
  }

  // Receive the key exchange record
  Record recv_record;
  StatusCode status = this->socket_recv_record(&recv_record, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:receiveKeyExchange: Failed to receive key exchange data.");
    return StatusCode::Error;
  }

  // Ensure it's a key exchange record
  if (recv_record.hdr.record_type != REC_HANDSHAKE)
  {
    logger_->log("SslServer:receiveKeyExchange: Received record is not a Key Exchange message.");
    return StatusCode::Error;
  }
  uint8_t handshake_message_type = recv_record.data[0];
  if (handshake_message_type != HS_CLIENT_KEY_EXCHANGE)
  {
    logger_->log("SslServer:receiveKeyExchange: Received handshake record is not client key exchange.");
    return StatusCode::Error;
  }

  if (sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    EVP_PKEY *server_params = BIGNUMs_to_EVP_PKEY_DH(sslSharedInfo.dh_p_, sslSharedInfo.dh_g_, NULL);
    if (!server_params)
    {
      logger_->log("Failed to create DH EVP_PKEY.");
      return StatusCode::Error;
    }

    // Extract the client's public key
    const unsigned char *clientPubKeyPtr = reinterpret_cast<const unsigned char *>(recv_record.data + 1); // Skip the message type byte
    size_t clientPubKeyLen = recv_record.hdr.data_size - 1;
    EVP_PKEY *client_pub_key = d2i_PUBKEY(nullptr, &clientPubKeyPtr, clientPubKeyLen);
    if (!client_pub_key)
    {
      logger_->log("Failed to deserialize client's public DH key.");
      return StatusCode::Error;
    }

    // Prepare context for deriving the shared secret using server's DH key pair
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(this->dhKeyPair, nullptr); // Assumes this->dhKeyPair is already set up
    if (!derive_ctx)
    {
      logger_->log("Failed to create context for shared secret derivation.");
      EVP_PKEY_free(client_pub_key); // Clean up
      return StatusCode::Error;
    }

    if (EVP_PKEY_derive_init(derive_ctx) <= 0)
    {
      logger_->log("Failed to initialize shared secret derivation.");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(client_pub_key); // Clean up
      return StatusCode::Error;
    }

    if (EVP_PKEY_derive_set_peer(derive_ctx, client_pub_key) <= 0)
    {
      logger_->log("Failed to set peer's public key for derivation.");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(client_pub_key); // Clean up
      return StatusCode::Error;
    }

    // Determine buffer length for the shared secret
    size_t secret_len = 0;
    if (EVP_PKEY_derive(derive_ctx, nullptr, &secret_len) <= 0)
    {
      logger_->log("Failed to determine the length of the shared secret.");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(client_pub_key);
      return StatusCode::Error;
    }

    // Allocate the buffer and derive the shared secret
    std::vector<unsigned char> shared_secret(secret_len);
    if (EVP_PKEY_derive(derive_ctx, shared_secret.data(), &secret_len) <= 0)
    {
      logger_->log("Failed to derive the shared secret.");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(client_pub_key);
      return StatusCode::Error;
    }

    // Store the derived shared secret
    sslSharedInfo.pre_master_secret_.assign(shared_secret.begin(), shared_secret.end());
    logger_->log("DHE Key Exchange processed successfully.");

    // EVP_PKEY_CTX_free(derive_ctx);
    // EVP_PKEY_free(client_pub_key);
    // EVP_PKEY_free(server_params);
    return StatusCode::Success;
  }

  else if (sslSharedInfo.chosen_cipher_suite_ == TLS_RSA_WITH_AES_128_CBC_SHA_256)
  {
    EVP_PKEY *pkey = SSL_CTX_get0_privatekey(sslCtx_);
    if (!pkey)
    {
      logger_->log("SslServer:receiveKeyExchangeRSA: Failed to get private key from SSL context.");
      return StatusCode::Error;
    }

    // Initialize the decryption operation using the server's private key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0)
    {
      logger_->log("SslServer:receiveKeyExchangeRSA: Failed to initialize decryption context.");
      if (ctx)
        EVP_PKEY_CTX_free(ctx);
      return StatusCode::Error;
    }

    // Determine buffer size for decrypted pre-master secret
    size_t decryptedLen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &decryptedLen,
                         reinterpret_cast<unsigned char *>(recv_record.data) + 1, recv_record.hdr.data_size - 1) <= 0)
    {
      logger_->log("SslServer:receiveKeyExchangeRSA: Failed to determine decrypted pre-master secret length.");
      EVP_PKEY_CTX_free(ctx);
      return StatusCode::Error;
    }

    std::vector<unsigned char> decryptedPreMasterSecret(decryptedLen);
    if (EVP_PKEY_decrypt(ctx, decryptedPreMasterSecret.data(), &decryptedLen,
                         reinterpret_cast<unsigned char *>(recv_record.data) + 1, recv_record.hdr.data_size - 1) <= 0)
    {
      logger_->log("SslServer:receiveKeyExchangeRSA: Failed to decrypt pre-master secret.");
      EVP_PKEY_CTX_free(ctx);
      return StatusCode::Error;
    }

    sslSharedInfo.pre_master_secret_.assign(decryptedPreMasterSecret.begin(), decryptedPreMasterSecret.begin() + decryptedLen);
    logger_->log("SslServer:receiveKeyExchangeRSA: Pre-master secret decrypted successfully.");

    EVP_PKEY_CTX_free(ctx); // Free the decryption context
  }

  logger_->log("SslServer:receiveKeyExchange: Key exchange successfully processed.");
  return StatusCode::Success;
}

StatusCode SslServer::receive_finished(int client_id, SSLSharedInfo &sslSharedInfo)
{
  if (this->closed_)
  {
    logger_->log("SslServer:receiveFinished: Connection is closed.");
    return StatusCode::Error;
  }

  // Receive the Finished message
  Record recv_record;
  StatusCode status = Ssl::socket_recv_record(&recv_record, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:receiveFinished: Failed to receive Finished message.");
    return StatusCode::Error;
  }

  // Verify that the received record is a Finished message
  if (recv_record.data[0] != HS_FINISHED)
  {
    logger_->log("SslServer:receiveFinished: Incorrect message type, expected Finished.");
    return StatusCode::Error;
  }

  // Decrypt the verification code
  std::string decryptedVerificationCode;
  std::string encryptedVerificationCode(reinterpret_cast<char *>(recv_record.data + 1), recv_record.hdr.data_size - 1);
  if (!aes_decrypt(encryptedVerificationCode, sslSharedInfo.client_write_key_, sslSharedInfo.client_write_Iv_, decryptedVerificationCode))
  {
    logger_->log("SslServer:receiveFinished: Decryption failed.");
    return StatusCode::Error;
  }

  // Validate the decrypted verification code
  // Note: This step is simplified. In a real implementation, you'd compare the decrypted code to an expected value based on previous handshake messages.
  if (decryptedVerificationCode != "\xAB\xCD\xEF") // Example verification code check
  {
    logger_->log("SslServer:receiveFinished: Verification failed, decrypted code does not match.");
    return StatusCode::Error;
  }

  logger_->log("SslServer:receiveFinished: Finished message received and verified successfully.");
  return StatusCode::Success;
}

StatusCode SslServer::send_finished(int client_id, SSLSharedInfo &sslSharedInfo)
{
  if (this->closed_)
  {
    logger_->log("SslServer:send_finished: Connection is closed.");
    return StatusCode::Error;
  }

  // Simulate the generation of a verification code. In a real scenario, this would involve complex cryptographic operations.
  std::string verificationCode = "\xAB\xCD\xEF"; // Example mock verification code represented as a string

  // The verification code is supposed to be encrypted with session keys. Here, we're using the updated aes_encrypt function.
  std::string encryptedVerificationCode; // Will hold the encrypted verification code
  if (aes_encrypt(verificationCode, sslSharedInfo.server_write_key_, sslSharedInfo.server_write_Iv_, encryptedVerificationCode) != true)
  {
    logger_->log("SslServer:sendFinished: Encryption of verification code failed.");
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
  StatusCode status = Ssl::socket_send_record(record, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:sendFinished: Failed to send Finished message.");
    delete[] record.data; // Remember to free allocated memory on error
    return StatusCode::Error;
  }

  delete[] record.data; // Free the allocated memory
  logger_->log("SslServer:sendFinished: Finished message sent successfully.");
  return StatusCode::Success;
}

StatusCode SslServer::calculate_master_secret_and_session_keys(int client_id, SSLSharedInfo &sslSharedInfo)
{

  if (sslSharedInfo.pre_master_secret_.empty())
  {
    logger_->log("Pre-master secret is not set.\n");
    return StatusCode::Error;
  }

  // Assuming logger_ is accessible and SSLSharedInfo instance is named sslSharedInfo for both server and client

  // logger_->log("SSLSharedInfo Data\n");
  // logger_->log("Chosen TLS version: ");
  // logger_->log(std::to_string(sslSharedInfo.chosen_tls_version_));
  // logger_->log("Chosen Cipher Suite: ");
  // logger_->log(std::to_string(sslSharedInfo.chosen_cipher_suite_));
  // logger_->log("Client Random: ");
  // logger_->log(std::to_string(sslSharedInfo.client_random_));
  // logger_->log("Server Random: ");
  // logger_->log(std::to_string(sslSharedInfo.server_random_));

  // // For BIGNUM values, you will need to convert them to a readable format
  // char *dh_p_hex = BN_bn2hex(sslSharedInfo.dh_p_);
  // char *dh_g_hex = BN_bn2hex(sslSharedInfo.dh_g_);
  // logger_->log("DH Parameter p: ");
  // logger_->log(dh_p_hex ? dh_p_hex : "null");
  // logger_->log("DH Parameter g: ");
  // logger_->log(dh_g_hex ? dh_g_hex : "null");

  // // Free the allocated hex strings to prevent memory leaks
  // if (dh_p_hex)
  //   OPENSSL_free(dh_p_hex);
  // if (dh_g_hex)
  //   OPENSSL_free(dh_g_hex);

  // // Pre-master secret is binary data; for logging, convert it to hex or base64
  // std::string pre_master_secret_hex;
  // for (uint8_t byte : sslSharedInfo.pre_master_secret_)
  // {
  //   char buf[3];
  //   snprintf(buf, sizeof(buf), "%02x", byte);
  //   pre_master_secret_hex += buf;
  // }
  // logger_->log("Pre-Master Secret (Hex): ");
  // logger_->log(pre_master_secret_hex);

  // Step 1: Combine client and server random values
  std::vector<uint8_t> seed(8);

  sslSharedInfo.client_random_ = 4294967215;
  sslSharedInfo.server_random_ = 1938923769;
  std::memcpy(&seed[0], &sslSharedInfo.client_random_, sizeof(sslSharedInfo.client_random_));
  std::memcpy(&seed[4], &sslSharedInfo.server_random_, sizeof(sslSharedInfo.server_random_));

  // Step 2: Simplified PRF for Master Secret (for learning, not secure)
  std::vector<uint8_t> master_secret = simplifiedPRF(sslSharedInfo.pre_master_secret_, seed, 64);

  sslSharedInfo.master_secret_ = master_secret;
  // Step 3: Derive session keys (simplified)
  sslSharedInfo.client_write_key_ = std::vector<uint8_t>(master_secret.begin(), master_secret.begin() + 16);
  sslSharedInfo.server_write_key_ = std::vector<uint8_t>(master_secret.begin() + 16, master_secret.begin() + 32);
  sslSharedInfo.client_write_Iv_ = std::vector<uint8_t>(master_secret.begin() + 32, master_secret.begin() + 48);
  sslSharedInfo.server_write_Iv_ = std::vector<uint8_t>(master_secret.begin() + 48, master_secret.begin() + 64);

  sslSharedInfo.client_write_Iv_ = {134, 51, 254, 53, 224, 242, 194, 188, 65, 117, 187, 46, 10, 85, 87, 167};
  sslSharedInfo.server_write_Iv_ = {221, 161, 213, 20, 30, 206, 8, 70, 228, 102, 125, 208, 151, 1, 64, 182};
  // Derive session keys from the master secre

  // logger_->log("client write key size: ");
  // logger_->log(std::to_string(sslSharedInfo.client_write_Iv_.size()));

  // logger_->log("server write key size: ");
  // logger_->log(std::to_string(sslSharedInfo.server_write_Iv_.size()));

  // logger_->log("client seed: ");
  // std::string clientSeed(seed.begin(), seed.end());
  // logger_->log(clientSeed);
  // logger_->log("Client write key (Hex): " + toHexString(sslSharedInfo.client_write_key_));
  // logger_->log("Server write key (Hex): " + toHexString(sslSharedInfo.server_write_key_));

  // logger_->log("client write iv: ");
  // std::string clientWriteIv(sslSharedInfo.client_write_Iv_.begin(), sslSharedInfo.client_write_Iv_.end());
  // logger_->log(clientWriteIv);

  // logger_->log("server write iv: ");
  // std::string serverWriteIv(sslSharedInfo.server_write_Iv_.begin(), sslSharedInfo.server_write_Iv_.end());
  // logger_->log(serverWriteIv);

  logger_->log("Master secret and session keys calculated successfully for client ID: " + std::to_string(client_id));
  return StatusCode::Success;
}

SslClient *SslServer::handshake(int client_id)
{

  TCP *clientTcp = this->tcp_->socket_accept();
  if (clientTcp == nullptr)
  {
    logger_->log("SslServer:socket_accept: Error in accepting the connection on TCP level.");
    return nullptr;
  }

  logger_->log("SslServer:socket_accept: TCP connection accepted.");

  // clientTcp->logger_ = this->logger_;
  this->client_id_ += 1;

  SSLSharedInfo sslSharedInfo;
  SSLServerSession sslServerSession;

  sslServerSession.client_id = client_id;
  sslServerSession.tcpClient = clientTcp;

  client_id_to_server_session_[client_id] = sslServerSession;
  // 1. receive clientHello
  logger_->log("SslServer:handshake:Receiving clientHello.");
  StatusCode status = this->receive_hello(client_id, sslSharedInfo); // waiting for clientHello message
  if (status == StatusCode::Error)
  {
    logger_->log("SslServer:handshake:Error in receiving clientHello.");
    return nullptr;
  }
  // 2. send serverHello. ALready called in receiveHello()

  // 3. send certificate
  status = this->send_certificate(client_id, sslSharedInfo); // waiting for clientHello message
  if (status == StatusCode::Error)
    return nullptr;
  // 4. send key exchange parameters

  status = this->send_key_exchange(client_id, sslSharedInfo, sslServerSession); // waiting for clientHello message
  if (status == StatusCode::Error)
    return nullptr;
  // 5. send done message

  status = this->send_hello_done(client_id, sslSharedInfo); // waiting for clientHello message
  if (status == StatusCode::Error)
    return nullptr;

  // 6. receive client key exchange
  status = this->receive_key_exchange(client_id, sslSharedInfo, sslServerSession); // waiting for clientHello message
  if (status == StatusCode::Error)
    return nullptr;

  status = this->calculate_master_secret_and_session_keys(client_id, sslSharedInfo); // waiting for clientHello message
  if (status == StatusCode::Error)
    return nullptr;

  // 7. receive finished message
  status = this->receive_finished(client_id, sslSharedInfo); // waiting for clientHello message
  if (status == StatusCode::Error)
    return nullptr;
  // 8. send finished message
  status = this->send_finished(client_id, sslSharedInfo); // waiting for clientHello message
  if (status == StatusCode::Error)
    return nullptr;

  logger_->log("SslServer:handshake: TCP sockfd in SslClient constructor: " + std::to_string(clientTcp->sockfd_));
  sslServerSession.sslClient = new SslClient(clientTcp, sslSharedInfo);

  this->client_id_to_server_session_[client_id] = sslServerSession;
  this->client_id_to_shared_info_[client_id] = sslSharedInfo;

  return sslServerSession.sslClient;
}

StatusCode SslServer::receive_key_refresh_request(int client_id)
{

  if (this->closed_)
  {
    logger_->log("SslServer:receive_key_refresh_request: Connection is closed.");
    return StatusCode::Error;
  }

  // Receive the Finished message
  Record recv_record;
  StatusCode status = Ssl::socket_recv_record(&recv_record, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:receive_key_refresh_request: Failed to receive keys refresh request message.");
    return StatusCode::Error;
  }

  // Verify that the received record is a Finished message
  if (recv_record.data[0] != HS_KEYS_REFRESH)
  {
    logger_->log("SslServer:receive_key_refresh_request: Not keys refresh request message");
    return StatusCode::Error;
  }

  logger_->log("SslServer:receive_key_refresh_request: Keys refresh request message received successfully.");
  return StatusCode::Success;
}

void SslServer::handle_dhe(int client_id)
{

  this->client_id_to_server_session_[client_id].sslClient->messageCounter += 1;

  unsigned int clientMessageCounter = this->client_id_to_server_session_[client_id].sslClient->messageCounter;
  const unsigned int clientMessageThreshold = this->client_id_to_server_session_[client_id].sslClient->MESSAGE_THRESHOLD;

  if (clientMessageCounter == clientMessageThreshold)
  {

    SSLSharedInfo sslSharedInfo = client_id_to_shared_info_[client_id];
    SSLServerSession sslServerSession = client_id_to_server_session_[client_id];

    StatusCode status = receive_key_refresh_request(client_id);
    status = send_key_exchange(client_id, sslSharedInfo, sslServerSession);
    status = receive_key_exchange(client_id, sslSharedInfo, sslServerSession);
    status = calculate_master_secret_and_session_keys(client_id, sslSharedInfo);

    if (status == StatusCode::Success)
    {
      logger_->log("SslClient:handle_dhe: Successfully refreshed session keys.");
    }
    this->client_id_to_server_session_[client_id].sslClient->messageCounter = 0;
  }
}

SslClient *SslServer::socket_accept()
{
  if (this->closed_) // if the server is closed, returns NULL
  {
    logger_->log("SslServer:socket_accept:Cannot accept connections on a closed server.");
    return nullptr;
  }

  // Handshake
  SslClient *client = handshake(this->client_id_);

  if (client == nullptr)
  {
    logger_->log("SslClient:socket_accept:Failed in performing the handshake.");
    this->tcp_->socket_close(); // close the TCP
    this->tcp_->logger_ = nullptr;
    delete[] this->tcp_;
    this->tcp_ = nullptr;
    return nullptr;
  }

  logger_->log("SslClient:socket_accept:Successful in establishing an SSL connection with the server.");

  return client;
}

StatusCode SslServer::socket_listen(int max_clients)
{                    // Checks if the server is already closed and, if not, calls the socket_listen method on the tcp_ object to start listening for incoming client connections, with a specified maximum number (num_clients).
  if (this->closed_) // if the server is closed, returns -1
  {
    logger_->log("SslServer:socket_listen:Server is closed and cannot be started.");
    return StatusCode::Error;
  }
  logger_->log("SslServer:socket_listen:Starting server...");
  return this->tcp_->socket_listen(max_clients);
}

StatusCode SslServer::shutdown()
{
  if (this->closed_) // if the server is closed, returns -1
  {
    logger_->log("SslServer:shutdown:Server is already closed.");
    return StatusCode::Error;
  }

  // Shutdown the underlying TCP server
  StatusCode status = this->tcp_->socket_close();

  // // PENDING Clean up SSL client objects
  // while (!this->client_id_to_server_session_.empty())
  // {
  //   SslClient *sslClient = this->client_id_to_server_session_.back();
  //   this->client_id_to_server_session_.pop_back();
  //   if (sslClient != nullptr)
  //   {
  //     delete sslClient;
  //     sslClient = nullptr;
  //   }
  // }

  this->closed_ = true;
  logger_->log("SslServer:shutdown:Server has been shut down.");
  return StatusCode::Success;
}

StatusCode SslServer::broadcast(const std::string &msg)
{
  if (this->closed_) // if the server is closed, returns -1
  {
    logger_->log("SslServer:broadcast:Cannot broadcast on a closed server.\n");
    return StatusCode::Error;
  }

  logger_->log("SslServer:broadcast:Attempting to securely broadcast message to all clients."); // logs the broadcast attempt and the message content

  for (auto &pair : this->client_id_to_server_session_)
  {
    SSLServerSession &session = pair.second;

    // Check if associated SslClient exists
    if (!session.sslClient)
    {
      logger_->log("SslServer:broadcast: Missing SslClient for client ID " + std::to_string(pair.first));
      continue; // Skip this client if SslClient is missing
    }
    // Send the message using the SslClient's method, assume it exists and correctly encrypts the message
    StatusCode status = session.sslClient->socket_send_string(msg, session.tcpClient);
    if (status != StatusCode::Success)
    {
      logger_->log("SslServer:broadcast:Partial failure: Could not send the complete message to client ID " + std::to_string(pair.first));
      // Consider how you want to handle partial failures: stop the broadcast, log and continue, etc.
    }

    else
    {
      if (client_id_to_shared_info_[session.client_id].chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
      {

        handle_dhe(session.client_id);
      }
    }

  
  }
  logger_->log("SslServer:broadcast:Secure broadcast completed successfully.");
  return StatusCode::Success;
}

StatusCode SslServer::socket_send_string(int client_id, const std::string &send_string)
{

  StatusCode status = client_id_to_server_session_[client_id].sslClient->socket_send_string(send_string, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:socket_send_string:Failed in sending the message.");
  }
  else
  {
    logger_->log("SslServer:socket_send_string:Successful in sending the message.");
  }

  if (client_id_to_shared_info_[client_id].chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {

    handle_dhe(client_id);
  }

  return status;
}

StatusCode SslServer::socket_recv_string(int client_id, std::string *recv_string)
{
  StatusCode status = client_id_to_server_session_[client_id].sslClient->socket_recv_string(recv_string, client_id_to_server_session_[client_id].tcpClient);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:socket_recv_string:Failed in receiving the message.");
  }
  else
  {
    logger_->log("SslServer:socket_recv_string:Successful in receiving the message.");
  }

  if (client_id_to_shared_info_[client_id].chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256)
  {
    handle_dhe(client_id);
  }
  return status;
}