#ifndef TCP_H
#define TCP_H

#include <string>
#include <vector>
#include <netinet/in.h> // sockaddr_in, PF_INET

class Logger;

class TCP
{
public:
  TCP();          // constructor
  virtual ~TCP(); // destructor

  // both the methods allow for setting and getting a logger object, to log messages
  void set_logger(Logger *logger);
  Logger *get_logger() const;

  // both the methods are used for getting information about local socket's hostname and port number
  int get_hostname(std::string *hostname) const;
  int get_port(int *port) const;

  virtual int socket_listen(int num_ports); // SERVER: sets up the socket to listen for incomfing connections on specified ports
  virtual TCP *socket_accept();             // SERVER: waits for an incoming connection and returns a new TCP object represeting that connection

  virtual int socket_connect(const std::string &ip, int port); // CLIENT: used to initiate connection to a server at a specific IP and port

  // COMMON MEthODS USED BY BOTH, CLIENT and SERVER
  virtual ssize_t socket_send(const std::string &send_str); // COMMON: sends data over socket
  virtual ssize_t socket_send(const char *send_buff, size_t send_len);
  virtual ssize_t socket_recv(std::string *recv_str, size_t recv_len); // COMMON: receives data over socket
  virtual ssize_t socket_recv(char *recv_buff, size_t recv_len);

  virtual int socket_close(); // close the socket connection

protected:
  TCP(int sockfd, struct sockaddr_in sock_addr, socklen_t sock_addrlen); // used internally to create a new TCP object when an incoming connection is accepted

  // belore three are helper methods used to set up the socket
  int init();
  int open_socket();
  int bind_port();

  Logger *logger_;

private:
  int sockfd_;
  struct sockaddr_in sock_addr_;
  socklen_t sock_addrlen_;
};

#endif // TCP_H
