#ifndef SSLSERVER_H
#define SSLSERVER_H

#include "Ssl.h"
#include "SslClient.h"
#include "../common/Logger/Logger.h"

#include <string>
#include <vector>
#include <set>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <unordered_map>

class SslServer : public Ssl
{

public:
  SslServer(const std::string &certificate_path, const std::string &key_path);
  ~SslServer();

  struct SSLServerSession
  {
    std::vector<uint8_t> server_dh_private_key_; // Server's DH private key
    SslClient *sslClient;
    TCP *tcpClient;

    // Default constructor
    SSLServerSession()
        : server_dh_private_key_(NULL)
    {
      // Proper initialization of pointers, e.g., BN_new() for server_dh_private_key_
    }

    ~SSLServerSession()
    {
    }

    // Copy and move constructors/assignment operators should be handled appropriately
  };

  StatusCode socket_listen(int max_clients = 5);
  SslClient *socket_accept(); // blocking call
  StatusCode shutdown();
  StatusCode broadcast(const std::string &msg);
  bool server_supports(uint16_t tls_version);

  bool handle_dhe(int client_id);
  void clear_ssl_shared_info(SSLSharedInfo &sslSharedInfo);

  // For sending and receiving raw string data (application data)
  virtual StatusCode socket_send_string(int client_id, const std::string &send_string);
  virtual StatusCode socket_recv_string(int client_id, std::string *recv_string);

  // handshake methods
  StatusCode send_hello(int client_id, const std::string key_exchange_algorithm, SSLSharedInfo &sslSharedInfo);
  StatusCode receive_hello(int client_id, SSLSharedInfo &sslSharedInfo);
  StatusCode send_certificate(int client_id, SSLSharedInfo &sslSharedInfo);
  StatusCode send_key_exchange(int client_id, SSLSharedInfo &sslSharedInfo, SSLServerSession &sslServerSession);
  StatusCode send_hello_done(int client_id, SSLSharedInfo &ssSharedInfo);
  StatusCode receive_key_exchange(int client_id, SSLSharedInfo &sslSharedInfo, SSLServerSession &sslServerSession);
  StatusCode receive_finished(int client_id, SSLSharedInfo &sslSharedInfo);
  StatusCode send_finished(int client_id, SSLSharedInfo &sslSharedInfo);
  StatusCode calculate_master_secret_and_session_keys(int client_id, SSLSharedInfo &sslSharedInfo, int i);
  SslClient *handshake(int client_id);
  StatusCode receive_refresh_key_request(int client_id);
  StatusCode send_refresh_key_exchange(int client_id, SSLSharedInfo &sslSharedInfo, SSLServerSession &sslServerSession);
  StatusCode receive_refresh_key_exchange(int client_id, SSLSharedInfo &sslSharedInfo, SSLServerSession &sslServerSession);
   static Logger *logger_;

private:
  bool closed_;
  int client_id_;
  // SSLSharedInfo sslSharedInfo;

  std::set<uint16_t> supported_tls_versions_;
  SSL_CTX *sslCtx_; // SSL context for OpenSSL
  std::unordered_map<int, SSLServerSession> client_id_to_server_session_;
  std::unordered_map<int, SSLSharedInfo> client_id_to_shared_info_;
  std::vector<Ssl *> ssl_clients_;
};

#endif // SSLSERVER_H