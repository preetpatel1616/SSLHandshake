#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include "TCP.h"

class TcpClient : public TCP
{
public:
  TcpClient();
  ~TcpClient();

  StatusCode socket_connect(const std::string &serverIp, int serverPort) override;
  StatusCode socket_close() override;

  ssize_t socket_send_string(const std::string &send_string) override;
  ssize_t socket_recv_string(std::string *recv_string) override;
};

#endif // TCP_CLIENT_H
