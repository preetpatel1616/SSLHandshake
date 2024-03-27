#ifndef TCP_H
#define TCP_H

#include <string>
#include <vector>
#include "netinet/in.h" // sockaddr_in, PF_INET
#include "../common/StatusCodes.h"

class Logger;

class TCP
{
public:
  TCP();          // constructor
  virtual ~TCP(); // destructor

  // three are helper methods used to set up the socket
  StatusCode init();
  StatusCode open_socket();
  StatusCode bind_to_port();

  virtual StatusCode socket_listen(int max_clients);                              // SERVER: sets up the TCP socket to listen for incoming connections. num_ports is the maximum number of clients allowed in the buffer/queue
  virtual TCP *socket_accept();                                                   // SERVER: accepts an incoming connection request on the listening socket, and returns a new TCP object representing the connection. This method blocks until a new connection is established
  virtual StatusCode socket_connect(const std::string &serverIp, int serverPort); // CLIENT: initiates a connection to a remote server specified by IP and port
  virtual StatusCode socket_close();                                              // COMMON: closes the TCP socket, terminating the connection

  // COMMON MEthODS USED BY BOTH, CLIENT and SERVER
  virtual ssize_t socket_send_string(const std::string &send_string); // COMMON: send data over the TCP connection
  ssize_t socket_send_buffer(const char *send_buffer, size_t total_send_buffer_length);
  // virtual ssize_t socket_recv_string(std::string *recv_string); // COMMON: receive data from the TCP connection
  ssize_t socket_recv_buffer(char *i_recv_buff, uint16_t recv_exp_len);

  int get_hostname(std::string *hostname) const; // retreives the hostname associated with the TCP connection
  StatusCode get_port(int *port) const;          // gets the port number on which the TCP socket is listening or connected

  Logger *logger_ = nullptr; // pointer to Logger object

protected:
  TCP(int sock_fd, struct sockaddr_in sock_addr, socklen_t sock_addrlen); // used internally to create a new TCP object when an incoming connection is accepted

private:
  int sockfd_;
  struct sockaddr_in sock_addr_ // 'sockaddr_in' is a structure that holds internet address information
  {
  };
  socklen_t sock_addrlen_;
};

#endif // TCP_H
