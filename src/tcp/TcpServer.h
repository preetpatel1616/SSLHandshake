#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include "TCP.h"
#include <string>
#include <vector>

class TcpServer : public TCP
{
public:
  TcpServer();
  ~TcpServer();

  StatusCode socket_listen(int max_clients = 1000) override;
  TCP *socket_accept() override; // blocking call
  StatusCode shutdown();
  StatusCode broadcast(const std::string &message);

  std::vector<TCP *> get_clients() const;

private:
  std::vector<TCP *> clients_; // List of pointers to client connections
  bool closed_;
};

#endif // TCP_SERVER_H
