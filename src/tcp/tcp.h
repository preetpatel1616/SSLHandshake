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

  void set_logger(Logger *logger); // assigns a logger to the TCP object for logging purposes
  Logger *get_logger() const; // returns the logger associated with the TCP object

  int get_hostname(std::string *hostname) const; // retreives the hostname associated with the TCP connection
  int get_port(int *port) const;                 // gets the port number on which the TCP socket is listening or connected

  virtual int socket_listen(int num_ports); // SERVER: sets up the TCP socket to listen for incomfing connections on a specified port
  virtual TCP *socket_accept();             // SERVER: accepts an incoming connection request on the listening socket, and returns a new TCP object representing the connection. This method blocks until a new connection is established

  virtual int socket_connect(const std::string &ip, int port); // CLIENT: initiates a connection to a remote server specified by IP and port

  // COMMON MEthODS USED BY BOTH, CLIENT and SERVER
  virtual ssize_t socket_send(const std::string &send_str); // COMMON: send data over the TCP connection
  virtual ssize_t socket_send(const char *send_buff, size_t send_len);
  virtual ssize_t socket_recv(std::string *recv_str, size_t recv_len); // COMMON: receive data from the TCP connection
  virtual ssize_t socket_recv(char *recv_buff, size_t recv_len);

  virtual int socket_close(); // COMMON: closes the TCP socket, terminating the connection

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
