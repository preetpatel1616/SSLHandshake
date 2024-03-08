#include "tcp_client.h"

#include <stdlib.h>

#include "logger.h"
#include "utils.h"

using namespace std;

TcpClient::TcpClient()
{ // constructor: initializes the TcpClient object
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0)
  {
    exit(1);
  }

  datetime = get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  set_logger(new Logger("client_" + datetime + ".log")); // initiates a new logger
  this->logger_->log("Client Log at " + datetime);       // logs a message indicating when the client log was started
}

TcpClient::~TcpClient()
{ // destructor
  if (this->logger_)
  {
    delete this->logger_;
    set_logger(NULL);
  }
}

int TcpClient::connect(const std::string &ip, int port)
{                                  // uses provided IP and por to establish a connection with the server
  return socket_connect(ip, port); // TCP Method
}

ssize_t TcpClient::send(const std::string &send_str)
{                               // sends the given string of daa over the TCP connection
  return socket_send(send_str); // TCP Method
}

ssize_t TcpClient::recv(std::string *recv_str, size_t recv_len) // sends the given string of daa over the TCP connection
{
  return socket_recv(recv_str, recv_len); // TCP Method
}

int TcpClient::close()
{                        // closes the TCP connection
  return socket_close(); // TCP Method
}
