// The tcp.cc file contains the implementation of the TCP class defined in tcp.h

#include "TCP.h"
#include "../common/Logger/Logger.h"
#include "../common/Utils/Utils.h"
#include <cstring>
#include <sys/socket.h>
#include <netdb.h>  // gethostbyname
#include <unistd.h> // close
#include <iostream>

// Constants
#define BIND_PORT_MIN 20000
#define BIND_PORT_MAX 20200
#define MAX_BUFFER_CHUNK_SIZE 1024

using namespace std;

// Constructor & Destructor

TCP::TCP()
{
  // What does "new" do?
  // 1. Allocates memory to hold an object of the given type.
  // 2. Calls the constructor to initialize the object (if it's a class type).
  // 3. Returns a pointer to the allocated memory
  this->logger_ = new Logger("tcp_default.log");
  if (this->init() != StatusCode::Success)
  {
    this->logger_->log("TCP:constructor:TCP object creation failed.");
    exit(1);
  }
}

TCP::TCP(int sockfd, struct sockaddr_in sock_addr, socklen_t sock_addrlen) // socket file descriptor, pointer to the socket address structure, and the length of this structure
{
  std::string filename = "tcp_" + std::to_string(sockfd) + ".log";
  this->logger_ = new Logger(filename);
  logger_->log("TCP:constructor:Creating TCP object with provided socket details.");
  if (sockfd < 0)
  {
    logger_->log("Invalid socket file descriptor provided.");
  }
  else
  {
    this->sockfd_ = sockfd;
    this->sock_addr_ = sock_addr;
    this->sock_addrlen_ = sock_addrlen;
    logger_->log("TCP:constructor:TCP object created successfully.");
  }
}

TCP::~TCP()
{
  if (this->sockfd_ != -1)
  {
    this->socket_close(); // closing the socket
  }

  this->logger_->log("TCP:deconstructor:TCP object is being destroyed.");
  delete this->logger_;
  this->logger_ = nullptr;
}

StatusCode TCP::init()
{
  logger_->log("TCP:init:Initializing TCP object.");
  // clearing garbage values, if any
  this->sockfd_ = -1;

  // assigning values
  this->sock_addr_.sin_family = AF_INET;
  this->sock_addr_.sin_addr.s_addr = INADDR_ANY;
  this->sock_addr_.sin_port = htons(0);
  this->sock_addrlen_ = sizeof(this->sock_addr_);
  // memset(&this->sock_addr_, 0, this->sock_addrlen_); // memset is used to fill a block of memory with a particular value

  if (this->open_socket() != StatusCode::Success)
  {
    logger_->log("TCP:init:Failed to open socket.");
    return StatusCode::Error;
  }

  if (this->bind_to_port() != StatusCode::Success)
  {
    logger_->log("TCP:init:Failed to bind port.");
    return StatusCode::Error;
  }
  logger_->log("TCP:init:TCP object created successfully.");

  return StatusCode::Success;
}

StatusCode TCP::open_socket() // COMMON: creates a socket
{
  logger_->log("TCP:open_socket:Attempting to open a TCP socket.");
  // returns -1 if error
  this->sockfd_ = socket(PF_INET, SOCK_STREAM, 0);
  if (this->sockfd_ < 0)
  {
    logger_->log("TCP:open_socket:Failed to open a TCP socket.");
    return StatusCode::Error;
  }
  logger_->log("TCP:open_socket:TCP socket opened successfully.");
  return StatusCode::Success;
}

StatusCode TCP::bind_to_port() // SERVER: associates the socket created by "open_socket" with a specified IP and port
{
  logger_->log("TCP:bind_to_port:Attempting to bind the socket to port.");
  for (unsigned short port = BIND_PORT_MIN; port <= BIND_PORT_MAX; port++)
  {
    this->sock_addr_.sin_port = htons(port);
    if (bind(this->sockfd_, (const struct sockaddr *)&this->sock_addr_, this->sock_addrlen_) == 0)
    {
      logger_->log("TCP:bind_to_port: Port = " + std::to_string(port) + " SockFd = " + std::to_string(this->sockfd_));
      logger_->log("TCP:bind_to_port:Port bound successfully on " + std::to_string(port));
      return StatusCode::Success;
    }
  }
  logger_->log("TCP:bind_to_port:Failed to bind port.\n");
  return StatusCode::Error;
}

// listen(), accept(), connect()

StatusCode TCP::socket_listen(int max_clients) // SERVER: sets up the TCP socket to listen for incoming connections on a specified port
{
  logger_->log("TCP:socket_listen:Setting socket to listen.");
  if (listen(this->sockfd_, max_clients) == 0)
  {
    logger_->log("TCP:socket_listen:Socket now listening.");
    return StatusCode::Success;
  }
  else
  {
    logger_->log("TCP:socket_listen:Failed to set socket to listen.");
    return StatusCode::Error;
  }
}

TCP *TCP::socket_accept() // SERVER: accepts an incoming connection request on the listening socket, and returns a new TCP object representing the connection. This method blocks until a new connection is established
{
  logger_->log("TCP:socket_accept:Waiting to accept a new connection.");
  // creates and assigns client socket related details
  struct sockaddr_in client_sock_addr; // socket address = ip:port | sockaddr_in is used for IPv4
  socklen_t client_sock_addrlen = sizeof(client_sock_addr);
  int client_sockfd = accept(this->sockfd_, (struct sockaddr *)&client_sock_addr, &client_sock_addrlen);

  if (client_sockfd < 0)
  {
    logger_->log("TCP:socket_accept:Error accepting new connection.");
    return nullptr;
  }
  else
  {
    logger_->log("TCP:socket_accept:New TCP connection accepted.");
    return new TCP(client_sockfd, client_sock_addr, client_sock_addrlen);
  }
}

StatusCode TCP::socket_connect(const std::string &serverIp, int serverPort) // CLIENT: initiates a connection to a remote server specified by IP and port
{
  logger_->log("TCP:socket_connect:Attempting to connect to server " + serverIp + ":" + std::to_string(serverPort) + ".\n");

  struct sockaddr_in server_sock_addr;

  socklen_t server_sock_addrlen_;

  struct hostent *host; // a pointer to a 'hostent' structure that will contain information about the host (server) such as the IP

  memset(&server_sock_addr, 0, sizeof(server_sock_addr)); // initializes the cxn_addr structure with zeroes to prevent any garbage values

  server_sock_addr.sin_family = AF_INET; // sets the address family to AF_INET, meaning that the address is IPv4

  server_sock_addr.sin_port = htons(serverPort);

  server_sock_addrlen_ = sizeof(server_sock_addr);

  host = gethostbyname(serverIp.c_str());

  memcpy(&server_sock_addr.sin_addr, host->h_addr_list[0], host->h_length);

  int status = connect(this->sockfd_, (struct sockaddr *)&server_sock_addr, server_sock_addrlen_); // connect(client's fd, server's socket address, server's socket address length)
  if (status == -1)
  {
    logger_->log("TCP:socket_connect:Failed to connect with the server.");
    return StatusCode::Error;
  }
  logger_->log("TCP:socket_connect:Successfully connected with the server.");
  return StatusCode::Success;
}

StatusCode TCP::socket_close() // COMMON: closes the TCP socket, terminating the connection
{
  logger_->log("TCP:socket_close:Closing the socket.");
  if (close(this->sockfd_) != 0)
  {
    logger_->log("TCP:socket_close:Failed to close the socket.");
    return StatusCode::Error;
  }
  logger_->log("TCP:socket_close:Socket closed successfully.");
  return StatusCode::Success;
}

ssize_t TCP::socket_send_string(const std::string &send_string) // COMMON: send data over the TCP connection
{                                                               // this function sends the actual bytes that make up the string over the network and is not sending a refernce or a pointer
  logger_->log("TCP:socket_send_string:Sending string data: " + send_string + "\n");
  ssize_t send_string_length = send(this->sockfd_, send_string.c_str(), send_string.size(), 0); // send(a,b,c) is an inbuilt function | this is used in socket_send_record()
  if (send_string_length == -1)
  {
    // Log the send failure
    logger_->log("TCP:socket_send_string: Failed to send data.\n");
    return -1; // StatusCode::Error won't work here.
  }
  else if (send_string_length < static_cast<ssize_t>(send_string.size()))
  {
    // Log if not all bytes were sent
    logger_->log("TCP:socket_send_string: Partial data sent.\n");
    return send_string_length;
  }
  else
  {
    // Log successful send
    logger_->log("TCP:socket_send_string: Data sent successfully.\n");
  }

  return send_string_length;
}

ssize_t TCP::socket_send_buffer(const char *send_buffer, size_t total_send_buffer_length)
{
  size_t remain_send_len = total_send_buffer_length;
  ssize_t send_total_len = 0;
  ssize_t send_len;
  const long unsigned int max_chunk_size = MAX_BUFFER_CHUNK_SIZE; // Assuming MAX_BUFFER_CHUNK_SIZE is defined somewhere
  int send_flags = 0;

  while (remain_send_len > 0)
  {
    const char *chunk_start = send_buffer + (total_send_buffer_length - remain_send_len);
    send_len = remain_send_len > max_chunk_size ? max_chunk_size : remain_send_len;
    send_len = send(this->sockfd_, chunk_start, send_len, send_flags);
    if (send_len == -1)
    {
      perror("error when sending");
      return -1;
    }
    remain_send_len -= send_len;
    send_total_len += send_len;
  }

  if (this->logger_ != NULL)
  {
    this->logger_->log("sent:");
    this->logger_->log_raw(send_buffer, send_total_len);
  }

  return send_total_len;
}

ssize_t TCP::socket_recv_string(std::string *recv_string) // COMMON: receive data from the TCP connection
{
  // In this function, the received string data is stored in the buffer array that is dynamically allocated at the beginning of the function. After receiving the data from the network into this buffer, it's then converted to a std::string object and assigned to the recv_string parameter, which is a pointer to a std::string object provided by the caller of the function.
  if (!recv_string)
  {
    logger_->log("TCP::socket_recv_string: Invalid string pointer.");
    return -1;
  }

  // allocate a buffer to hold the received data
  char *buffer = (char *)malloc(5 * sizeof(char));
  ssize_t bytes_received = socket_recv_buffer(buffer, 5);

  std::string received_string = std::string(buffer);

  logger_->log("TCP::socket_recv_string: Received data successfully.");
  return bytes_received;
}

ssize_t TCP::socket_recv_buffer(char *recv_buffer, size_t recv_exp_len)
{
  size_t remain_recv_len = recv_exp_len;
  ssize_t recv_total_len = 0;
  ssize_t recv_len;
  const long unsigned int max_chunk_size = MAX_BUFFER_CHUNK_SIZE; // Assuming MAX_BUFFER_CHUNK_SIZE is defined somewhere
  int recv_flags = 0;

  while (remain_recv_len > 0)
  {
    recv_len = remain_recv_len > max_chunk_size ? max_chunk_size : remain_recv_len;
    recv_len = recv(this->sockfd_, recv_buffer + (recv_exp_len - remain_recv_len), recv_len, recv_flags);
    if (recv_len == -1)
    {
      perror("error when receiving");
      return -1;
    }
    remain_recv_len -= recv_len;
    recv_total_len += recv_len;
  }

  if (this->logger_ != NULL)
  {
    this->logger_->log("received:");
    this->logger_->log_raw(recv_buffer, recv_total_len);
  }

  return recv_total_len;
}

int TCP::get_hostname(std::string *hostname) const // retrieves the hostname associated with the TCP connection
{
  // std::string is a C++ container that holds text, similar to how a std::vector might hold numbers

  // Check if the pointer to the string is valid.
  if (hostname)
  {
    return get_publichostname(hostname);
  }
  else
  {
    // If the hostname pointer is null, return an error code.
    return -1;
  }
}

StatusCode TCP::get_port(int *port) const // gets the port number on which the TCP socket is listening or connected
{
  if (port != nullptr)
  {
    *port = (int)ntohs(this->sock_addr_.sin_port); // puts the port value in the memory. So now 'port' points to the memory where port value is stored
    return StatusCode::Success;
  }
  return StatusCode::Error;
}
