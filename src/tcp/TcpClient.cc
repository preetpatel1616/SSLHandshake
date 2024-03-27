#include "TcpClient.h"
#include "../common/Logger/Logger.h"
#include "../common/Utils/Utils.h"
#include <stdlib.h>

using namespace std;

TcpClient::TcpClient()
{ // constructor: initializes the TcpClient object
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0)
  {
    exit(1);
  }

  this->logger_ = new Logger("client_" + datetime + ".log");                                // The logger filename includes the current date and time
  this->logger_->log("TcpClient:constructor:TcpClient object created. Log at " + datetime); // logs a message indicating when the client log was started
}

TcpClient::~TcpClient()
{

  StatusCode status = this->socket_close();
  // deleting the socket
  if (status != StatusCode::Success)
  {
    if (this->logger_)
    {
      this->logger_->log("TcpClient:deconstructor:Failed to close socket.");
    }
  }
  else
  {
    if (this->logger_)
    {
      this->logger_->log("TcpClient:deconstructor:Socket closed successfully.");
    }
  }
  // deleting the logger object
  if (this->logger_)
  {
    this->logger_->log("TcpClient:deconstructor:TcpClient object is being destroyed.");
    delete this->logger_;
    this->logger_ = nullptr;
  }
}

StatusCode TcpClient::socket_connect(const std::string &serverIp, int serverPort)
{                                                                // uses provided IP and por to establish a connection with the server
  StatusCode status = TCP::socket_connect(serverIp, serverPort); // TCP Method
  if (status != StatusCode::Success)
  {
    logger_->log("TcpClient:socket_connect:TcpClient failed to connect.\n");
  }
  else
  {
    logger_->log("TcpClient:socket_connect:TcpClient connected successfully.\n");
  }
  return status;
}

ssize_t TcpClient::socket_send_string(const std::string &send_string)
{ // sends the given string of daa over the TCP connection
  ssize_t send_string_length = TCP::socket_send_string(send_string);
  if (send_string_length < 0)
  {
    logger_->log("TcpClient:socket_send_string:Send failed.");
    return -1;
  }
  else
  {
    logger_->log("TcpClient:socket_send_string:Sent data successfully.");
  }
  return send_string_length;
}

// ssize_t TcpClient::socket_recv_string(std::string *recv_string) // sends the given string of daa over the TCP connection
// {
//   ssize_t received_string_length = TCP::socket_recv_string(recv_string);
//   if (received_string_length < 0)
//   {
//     logger_->log("TcpClient:socket_recv_string:Receive failed.");
//     return -1;
//   }
//   else
//   {
//     logger_->log("TcpClient:socket_recv_string:TcpClient received data successfully.\n");
//   }
//   return received_string_length;
// }

StatusCode TcpClient::socket_close()
{
  // closes the TCP connection
  StatusCode status = TCP::socket_close(); // TCP Method
  if (status != StatusCode::Success)
  {
    logger_->log("TcpClient:socket_close:Failed to close the socket.");
  }
  else
  {
    logger_->log("TcpClient:socket_close:Socket closed successfully.");
  }
  return status;
}
