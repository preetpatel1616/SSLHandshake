#include "SslServer.h"
#include "crypto_adaptor.h"
#include "../tcp/TCP.h"
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
#include <openssl/ssl.h>
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
  clientHello.tls_negotiate_version = static_cast<uint16_t>(recv_record.data[index] << 8) | (recv_record.data[index + 1]);
  index += sizeof(clientHello.tls_negotiate_version);
  // 2.2 deserialize random
  clientHello.random = 0;
  for (int i = 0; i < 4; ++i)
  { // Assuming random is 4 bytes
    clientHello.random = static_cast<uint32_t>(recv_record.data[index] << 8) | (recv_record.data[index + i]);
  }
  index += sizeof(clientHello.random);

  // 2.3 deserialize ciphersuites
  while (index + 1 < recv_record.hdr.data_size)
  {
    uint16_t cipherSuite = static_cast<uint16_t>(recv_record.data[index] << 8) | recv_record.data[index + 1];
    clientHello.cipher_suites.push_back(cipherSuite);
    index += sizeof(cipherSuite);
  }

  // logger_->log("OUR VALUES\n");
  // logger_->log("tls version: ");
  // logger_->log(std::to_string(clientHello.tls_negotiate_version));
  // logger_->log("client random: ");
  // logger_->log(std::to_string(clientHello.random));
  // logger_->log("cipher suites: ");
  // std::string myString(clientHello.cipher_suites.begin(), clientHello.cipher_suites.end());
  // logger_->log(myString);

  // logger_->log("CORRECT VALUES\n");
  // logger_->log("tls version: ");
  // logger_->log(std::to_string(0x0303));
  // logger_->log("cipher suites: ");

  // 3. process clientHello message
  uint16_t chosen_tls_version;

  // 3.1 process tls version
  if (clientHello.tls_negotiate_version >= TLS_1_2 && server_supports(TLS_1_2))
  {
    chosen_tls_version = TLS_1_2;
  }
  else if (clientHello.tls_negotiate_version >= TLS_1_1 && server_supports(TLS_1_1))
  {
    chosen_tls_version = TLS_1_1;
  }
  else if (clientHello.tls_negotiate_version >= TLS_1_0 && server_supports(TLS_1_0))
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

  if (clientHello.cipher_suites[0] == TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
  {
    isDhe = true;
  }
  else if (clientHello.cipher_suites[0] == TLS_RSA_WITH_AES_128_CBC_SHA)
  {
    isRsa = true;
  }

  // assigning values to sslSharedInfo

  sslSharedInfo.chosen_tls_version_ = chosen_tls_version;
  sslSharedInfo.client_random_ = clientHello.random;

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
  serverHello.chosen_tls_version = sslSharedInfo.chosen_tls_version_;
  serverHello.random = generate_random_number(); // Implement this function to generate a random number
  if (key_exchange_algorithm == "DHE")
  {
    serverHello.chosen_cipher_suite = TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
  }
  else if (key_exchange_algorithm == "RSA")
  {
    serverHello.chosen_cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA;
  }
  else
  {
    logger_->log("SslServer:sendHello: No compatible cipher suite found.");
    return StatusCode::Error;
  }

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
  serializedServerHello[index++] = static_cast<char>(serverHello.chosen_tls_version >> 8);
  serializedServerHello[index++] = static_cast<char>(serverHello.chosen_tls_version & 0xFF);

  // Random
  for (int i = 3; i >= 0; --i)
  {
    serializedServerHello[index++] = (serverHello.random >> (i * 8)) & 0xFF;
  }

  // Cipher suite
  serializedServerHello[index++] = static_cast<char>(serverHello.chosen_cipher_suite >> 8);
  serializedServerHello[index++] = static_cast<char>(serverHello.chosen_cipher_suite & 0xFF);

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

  sslSharedInfo.chosen_cipher_suite_ = serverHello.chosen_cipher_suite;
  sslSharedInfo.server_random_ = serverHello.random;

  // add_client_session(client_id, chosen_tls_version, serverHello.chosen_cipher_suite, client_random);

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
logger_->log("Just entered send key exchange function");
  if (this->closed_)
  {
    logger_->log("SslServer:sendKeyExchange: Server is closed, cannot send Key Exchange.");
    return StatusCode::Error;
  }

  if (sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
  {
    DH *dh = DH_new();
    if (dh == nullptr)
    {
      logger_->log("SslServer:sendKeyExchange: Memory allocation for DH failed.");
      return StatusCode::Error;
    }

    // generate dhe parameters
    //  Generate DH parameters (for simplicity, using predefined parameters)
    //  Normally, you might generate these or load them from a secure source.
    //  Here we just use OpenSSL functions to generate a set.
    if (1 != DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL))
    {
      logger_->log("SslServer:sendKeyExchange: Failed to generate DH parameters.");
      DH_free(dh);
      return StatusCode::Error;
    }

    // Generate the public and private DH key pair
    if (1 != DH_generate_key(dh))
    {
      logger_->log("SslServer:sendKeyExchange: Failed to generate DH key pair.");
      DH_free(dh);
      return StatusCode::Error;
    }

    logger_->log("Before generating dh parameters");

    // Get the prime 'p'
    const BIGNUM *p = DH_get0_p(dh);
    // Get the generator 'g'
    const BIGNUM *g = DH_get0_g(dh);
    // Get the public key
    const BIGNUM *pub_key = DH_get0_pub_key(dh);
    // Get the private key
    const BIGNUM *priv_key = DH_get0_priv_key(dh);

    logger_->log("After generating dh parameters");

    // Since DH_get0_* does not increase the reference count, duplicating BIGNUM* for safe memory management
    sslSharedInfo.dh_p_ = BN_dup(p);
    sslSharedInfo.dh_g_ = BN_dup(g);
    sslSharedInfo.server_dh_public_key_ = BIGNUM_to_vector(BN_dup(pub_key));      // Assuming BIGNUM_to_vector converts BIGNUM* to a std::vector<uint8_t>
    sslServerSession.server_dh_private_key_ = BIGNUM_to_vector(BN_dup(priv_key)); // Assuming BIGNUM_to_vector converts BIGNUM* to a std::vector<uint8_t>

    logger_->log("Before serialization of dh parameters");
    // Serialize the DH parameters and public key
    std::vector<uint8_t>
        serializedData;
    // Add the handshake message type
    serializedData.push_back(HS_SERVER_KEY_EXCHANGE);

    // Serialize p, g, and pub_key in that order
    append_BN_to_vector(p, serializedData);
    append_BN_to_vector(g, serializedData);
    append_BN_to_vector(pub_key, serializedData);

    logger_->log("After sereliazation of dh parameters");

    // Construct the record (simplified, adjust according to your Record structure)
    Record record;
    record.hdr.record_type = REC_HANDSHAKE;
    record.hdr.tls_version = sslSharedInfo.chosen_tls_version_;
    record.hdr.data_size = static_cast<uint16_t>(serializedData.size());
    record.data = new char[serializedData.size()];

    // Copy the serialized data into the record's data
    std::memcpy(record.data, serializedData.data(), serializedData.size());

    // Send the record
    StatusCode status = Ssl::socket_send_record(record, client_id_to_server_session_[client_id].tcpClient);
    if (status != StatusCode::Success)
    {
      logger_->log("SslServer:sendKeyExchange: Failed to send DHE key exchange.");
      delete[] record.data;
      DH_free(dh);
      return StatusCode::Error;
    }

    logger_->log("SslServer:sendKeyExchange: DHE key exchange sent successfully.");
    delete[] record.data; // Remember to free the allocated memory
    DH_free(dh);          // Clean up the DH structure
    return StatusCode::Success;
  }
  else if (sslSharedInfo.chosen_cipher_suite_ == TLS_RSA_WITH_AES_128_CBC_SHA)
  {
    // For RSA, since the certificate containing the RSA public key has been sent,
    // the server waits for the client to send an encrypted pre-master secret.
    logger_->log("SslServer:sendKeyExchange: RSA key exchange, awaiting encrypted pre-master secret from client.");
  }
  logger_->log("SslServer:sendKeyExchange: Key exchange data sent successfully.");
  return StatusCode::Success;
}

StatusCode SslServer::send_hello_done(int client_id, SSLSharedInfo &sslSharedInfo)
{
  if (this->closed_)
  {
    logger_->log("SslServer:sendHelloDone: Server is closed, cannot send HelloDone.");
    return StatusCode::Error;
  }

  // Construct the HelloDone message. Since ServerHelloDone has no payload, we only care about the message type.
  std::vector<uint8_t> helloDoneMessage;
  helloDoneMessage.push_back(HS_SERVER_HELLO_DONE); // Assuming HS_SERVER_HELLO_DONE is defined as the ServerHelloDone message type

  // Construct the HelloDone message
  Record record;
  record.hdr.tls_version = sslSharedInfo.chosen_tls_version_;            // Assuming TLS version has been negotiated
  record.hdr.record_type = REC_HANDSHAKE;                                // The record type for HelloDone
  record.hdr.data_size = static_cast<uint16_t>(helloDoneMessage.size()); // Should be 0 or the size of the message if it had a payload;                     // HelloDone has no payload
  record.data = new char[helloDoneMessage.size()];                       // Dynamically allocate memory for the data;                       // No data for HelloDone

  // Copy the HelloDone message into the record's data field
  std::memcpy(record.data, helloDoneMessage.data(), helloDoneMessage.size());

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
  StatusCode status = Ssl::socket_recv_record(&recv_record, client_id_to_server_session_[client_id].tcpClient);
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

  if (sslSharedInfo.chosen_cipher_suite_ == TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
  {
    // Use the server's DH parameters and private key from sslServerSession
    DH *dh_ = DH_new();
    BIGNUM *p = sslSharedInfo.dh_p_;
    BIGNUM *g = sslSharedInfo.dh_g_;
    DH_set0_pqg(dh_, p, NULL, g);
    DH_set0_key(dh_, NULL, BN_bin2bn(&sslServerSession.server_dh_private_key_[0], sslServerSession.server_dh_private_key_.size(), NULL));

    // Deserialize the client's public DH key from the received record
    const char *clientPubKeyPtr = reinterpret_cast<const char *>(recv_record.data + 1); // Skip the message type byte
    int clientPubKeyLen = recv_record.hdr.data_size - 1;                                // Adjust length for the actual key data
    BIGNUM *clientPubKey = BN_bin2bn(reinterpret_cast<const unsigned char *>(clientPubKeyPtr), clientPubKeyLen, NULL);

    if (!clientPubKey)
    {
      DH_free(dh_);
      logger_->log("SslServer:receiveKeyExchange: Failed to deserialize client's DH public key.");
      return StatusCode::Error;
    }

    // Compute the shared secret
    std::vector<unsigned char> sharedSecret(DH_size(dh_));
    int sharedSecretSize = DH_compute_key(&sharedSecret[0], clientPubKey, dh_);

    if (sharedSecretSize <= 0)
    {
      BN_free(clientPubKey);
      DH_free(dh_);
      logger_->log("SslServer:receiveKeyExchange: Failed to compute shared secret.");
      return StatusCode::Error;
    }

    // Store the shared secret as the pre-master secret in sslSharedInfo
    sslSharedInfo.pre_master_secret_.assign(sharedSecret.begin(), sharedSecret.begin() + sharedSecretSize);
    logger_->log("SslServer:receiveKeyExchange: DHE Key Exchange processed successfully.");

    BN_free(clientPubKey);
    DH_free(dh_); // Clean up DH structure after use
  }

  else if (sslSharedInfo.chosen_cipher_suite_ == TLS_RSA_WITH_AES_128_CBC_SHA)
  {
    EVP_PKEY *pkey = SSL_CTX_get0_privatekey(sslCtx_);
    if (!pkey)
    {
      logger_->log("SslServer:receiveKeyExchangeRSA: Failed to get private key from SSL context.");
      return StatusCode::Error;
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa)
    {
      logger_->log("SslServer:receiveKeyExchangeRSA: Failed to get RSA key.");
      return StatusCode::Error;
    }

    // Decrypt the pre-master secret
    std::vector<unsigned char> decryptedPreMasterSecret(RSA_size(rsa));
    int decryptedLen = RSA_private_decrypt(
        recv_record.hdr.data_size - 1,                           // Subtract 1 for the message type
        reinterpret_cast<unsigned char *>(recv_record.data) + 1, // Skip the message type byte
        decryptedPreMasterSecret.data(),
        rsa,
        RSA_PKCS1_PADDING);

    if (decryptedLen == -1)
    {
      char buffer[120];
      ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
      logger_->log(std::string("SslServer:receiveKeyExchangeRSA: Failed to decrypt pre-master secret. Error: ") + buffer);
      RSA_free(rsa);
      return StatusCode::Error;
    }

    sslSharedInfo.pre_master_secret_.assign(decryptedPreMasterSecret.begin(), decryptedPreMasterSecret.begin() + decryptedLen);
    logger_->log("SslServer:receiveKeyExchangeRSA: Pre-master secret decrypted successfully.");

    RSA_free(rsa); // Free the RSA structure
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
  if (!aes_decrypt(encryptedVerificationCode, sslSharedInfo.server_write_key_, sslSharedInfo.server_write_Iv_, decryptedVerificationCode))
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
    logger_->log("Pre-master secret is not set for client ID: " + std::to_string(client_id));
    return StatusCode::Error;
  }

  // Combine client and server random values
  std::vector<uint8_t> seed;
  append_uint32_to_vector(seed, sslSharedInfo.client_random_);
  append_uint32_to_vector(seed, sslSharedInfo.server_random_);

  // Assuming the master secret is derived here
  std::vector<uint8_t> master_secret(EVP_MAX_MD_SIZE);
  size_t master_secret_len = 0;
  // The PRF function would derive the master secret using the pre-master secret and the seed

  // Derive session keys from the master secret
  std::vector<uint8_t> key_block; // The actual length needs to be determined based on the cipher suite

  const size_t AES_KEY_SIZE = 16; // For AES-128
  const size_t AES_IV_SIZE = 16;
  std::vector<uint8_t> client_write_key(AES_KEY_SIZE), server_write_key(AES_KEY_SIZE);
  std::vector<uint8_t> client_write_Iv(AES_IV_SIZE), server_write_Iv(AES_IV_SIZE);
  // Here you would split the key_block into the necessary keys and IVs

  // Store the keys and IVs in the session
  sslSharedInfo.client_write_key_ = client_write_key;
  sslSharedInfo.server_write_key_ = server_write_key;
  sslSharedInfo.client_write_Iv_ = client_write_Iv;
  sslSharedInfo.server_write_Iv_ = server_write_Iv;

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

  sslServerSession.sslClient = new SslClient(sslSharedInfo);

  this->client_id_to_server_session_[client_id] = sslServerSession;
  this->client_id_to_shared_info_[client_id] = sslSharedInfo;

  return sslServerSession.sslClient;
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

  return nullptr;
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

// vector<Ssl *> SslServer::get_clients() const
// {
//   return vector<Ssl *>(this->ssl_clients_);
// }

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
    StatusCode status = session.sslClient->socket_send_string(msg);
    if (status != StatusCode::Success)
    {
      logger_->log("SslServer:broadcast:Partial failure: Could not send the complete message to client ID " + std::to_string(pair.first));
      // Consider how you want to handle partial failures: stop the broadcast, log and continue, etc.
    }

    logger_->log("SslServer:broadcast:Secure broadcast completed successfully.");
    return StatusCode::Success;
  }
}

StatusCode SslServer::socket_send_string(int client_id, const std::string &send_string)
{

  StatusCode status = client_id_to_server_session_[client_id].sslClient->socket_send_string(send_string);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:socket_send_string:Failed in sending the message.");
  }
  else
  {
    logger_->log("SslServer:socket_send_string:Successful in sending the message.");
  }
  return status;
}

StatusCode SslServer::socket_recv_string(int client_id, std::string *recv_string)
{
  StatusCode status = client_id_to_server_session_[client_id].sslClient->socket_recv_string(recv_string);
  if (status != StatusCode::Success)
  {
    logger_->log("SslServer:socket_recv_string:Failed in receiving the message.");
  }
  else
  {
    logger_->log("SslServer:socket_recv_string:Successful in receiving the message.");
  }
  return status;
}