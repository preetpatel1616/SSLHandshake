#ifndef SSLCLIENT_H
#define SSLCLIENT_H

#include "Ssl.h"

#include <sys/types.h>

#include <string.h>
#include <vector>
#include <set>
#include <openssl/bn.h>
#include <openssl/x509.h>

class SslClient : public Ssl
{

private:
  std::set<uint16_t> supported_tls_versions;
  std::vector<uint16_t> supported_cipher_suites;
  std::vector<uint8_t> client_dh_private_key_; // Client's DH private key

public:
  SSLSharedInfo sslSharedInfo;
  SslClient();
  SslClient(const SSLSharedInfo &sslSharedInfo)
      : sslSharedInfo(sslSharedInfo) {}
  ~SslClient();

  unsigned int messageCounter = 0;
  const unsigned int MESSAGE_THRESHOLD = 3;

  // For sending and receiving raw string data (application data)

virtual StatusCode socket_send_string(const std::string &send_string, TCP* tcpInstance);
  virtual StatusCode socket_recv_string(std::string *recv_string, TCP* tcpInstance);

  StatusCode socket_connect(const std::string &server_ip, int server_port, std::string key_exchange_algorithm);
  void handle_dhe();
  StatusCode send_key_refresh_request();

      // Handshake methods
      StatusCode
      send_hello();
  StatusCode receive_hello();
  StatusCode receive_certificate();
  StatusCode receive_key_exchange();
  StatusCode receive_hello_done();
  StatusCode send_key_exchange();
  StatusCode send_finished();
  StatusCode receive_finished();
  StatusCode calculate_master_secret_and_session_keys();
  StatusCode handshake();
};

#endif // SSL_CLIENT_H