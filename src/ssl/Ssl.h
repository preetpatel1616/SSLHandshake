#ifndef SSL_H
#define SSL_H

#include "../common/Logger/Logger.h" // Logging support
#include "../tcp/TCP.h"              // TCP communication support
#include "../common/StatusCodes.h"   // Common status codes for error handling

#include <string>
#include <vector>
#include <openssl/bn.h>   // OpenSSL big number for cryptographic calculations
#include <openssl/x509.h> // OpenSSL X.509 for certificate handling
#include <stdint.h>       // Standard integer types

class TCP;
class Logger;

class Ssl
{
public:
  // Handshake message Types
  static const uint8_t HS_CLIENT_HELLO;
  static const uint8_t HS_SERVER_HELLO;
  static const uint8_t HS_CERTIFICATE;
  static const uint8_t HS_SERVER_KEY_EXCHANGE;
  static const uint8_t HS_CERTIFICATE_REQUEST;
  static const uint8_t HS_SERVER_HELLO_DONE;
  static const uint8_t HS_CERTIFICATE_VERIFY;
  static const uint8_t HS_CLIENT_KEY_EXCHANGE;
  static const uint8_t HS_FINISHED;
  static const uint8_t HS_KEYS_REFRESH;

  // Record Types
  static const uint8_t REC_CHANGE_CIPHER_SPEC;
  static const uint8_t REC_ALERT;
  static const uint8_t REC_HANDSHAKE;
  static const uint8_t REC_APP_DATA;

  // TLS versions

  static const uint16_t TLS_1_0; // 1.0
  static const uint16_t TLS_1_1; // 1.1
  static const uint16_t TLS_1_2; // 1.2

  // Cipher suites
  static const uint16_t TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256;
  static const uint16_t TLS_RSA_WITH_AES_128_CBC_SHA_256;

  // ClientHello structure for initiating communication
  struct ClientHello
  {
    uint16_t tls_negotiate_version_;      // The highest TLS version supported by the client
    uint32_t random_;                     // A client-generated random number
    std::vector<uint16_t> cipher_suites_; // List of supported cipher suites
  };

  // ServerHello structure for responding to the client
  struct ServerHello
  {
    uint16_t chosen_tls_version_; // The highest TLS version supported by the client
    uint32_t random_;             // A client-generated random number
    uint16_t chosen_cipher_suite_;
  };

  // RecordHeader and Record structures for encapsulating messages
  struct RecordHeader
  {                       // Metadata of the record
    uint8_t record_type;  // record type
    uint16_t tls_version; // TLS version
    uint16_t data_size;   // size of the encrypted data
  };

  // Record structure
  struct Record
  {                   // Records are the basic units of data exchange in SSL/TLS protocol
    RecordHeader hdr; // instant of RecordHeader structure
    char *data;       // actual data payload
  };

  // SSLSharedInfo structure holds shared information between client and server
  struct SSLSharedInfo
  {
    int client_id_;
    uint16_t chosen_tls_version_;
    uint16_t chosen_cipher_suite_;
    uint32_t client_random_;
    uint32_t server_random_;
    X509 *server_certificate_ = nullptr;
    BIGNUM *dh_p_ = nullptr; // DH parameter p
    BIGNUM *dh_g_ = nullptr; // DH parameter g
    std::vector<uint8_t> pre_master_secret_;
    std::vector<uint8_t> master_secret_;
    std::vector<uint8_t> client_write_key_;
    std::vector<uint8_t> server_write_key_;
    std::vector<uint8_t> client_write_Iv_;
    std::vector<uint8_t> server_write_Iv_;

    SSLSharedInfo()
        : chosen_tls_version_(0), chosen_cipher_suite_(0),
          client_random_(0), server_random_(0),
          server_certificate_(nullptr),
          dh_p_(nullptr), dh_g_(nullptr) {}

    ~SSLSharedInfo()
    {
      if (dh_p_)
        BN_free(dh_p_);
      if (dh_g_)
        BN_free(dh_g_);
      if (server_certificate_)
        X509_free(server_certificate_); // Free the X509 certificate
    }
  };

  Ssl();
  Ssl(TCP *tcp);
  virtual ~Ssl();

  // Utility methods for hostname and port
  std::string get_hostname() const;
  int get_port() const;

  // For sending and receiving raw string data (application data)
  virtual StatusCode socket_send_string(const std::string &send_string, std::vector<uint8_t> write_key, std::vector<uint8_t> write_Iv, TCP *tcpInstance);
  virtual StatusCode socket_recv_string(std::string *recv_string, std::vector<uint8_t> write_key, std::vector<uint8_t> write_Iv, TCP *tcpInstance);

  // For sending and receiving SSL Records
  virtual StatusCode socket_send_record(const Record &send_record, TCP *tcpInstance);
  virtual StatusCode socket_recv_record(Record *recv_record, TCP *tcpInstance);
  TCP *tcp_; // a pointer to a TCP object
  EVP_PKEY *dhKeyPair = nullptr;

protected:
  Logger *logger_ = nullptr; // a pointer to a Logger object

};

#endif // SSL_H