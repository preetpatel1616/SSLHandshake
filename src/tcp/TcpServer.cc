#include "TcpServer.h"
#include "../common/Logger/Logger.h"
#include "../common/Utils/Utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <iostream>
#include <fstream>

using namespace std;

TcpServer::TcpServer()
{ // Constructor: Initializes the TcpServer object and sets up a logger to log server activity
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0)
  {
    exit(1);
  }
  this->logger_ = new Logger("server_" + datetime + ".log"); // The logger filename includes the current date and time
  this->logger_->log("TcpServer:constructor:TcpServer object created. Server Log at " + datetime);
  this->closed_ = false; // indicating the server is open to start and accept connections
}

TcpServer::~TcpServer()
{ // Destructor
  if (!this->closed_)
  { // Closes any active connections
    this->shutdown();
  }
  if (this->logger_) // checking if the logger is a nullptr
  {                  // Deletes the logger object and sets the logger pointer to NULL
    this->logger_->log("TcpServer:deconstructor:TcpServer object is being destroyed.");
    delete this->logger_;
    this->logger_ = nullptr; // setting the logger pointer to null after it is being deleted
  }
}

StatusCode TcpServer::socket_listen(int max_client)
{
  if (this->closed_) // if the server is closed, returns -1
  {
    logger_->log("TcpServer:socket_listen:Server is closed and cannot be started.");
    return StatusCode::Error;
  }
  logger_->log("TcpServer:socket_listen:Starting server...");
  return TCP::socket_listen(max_client); // TCP method | If the server is open, then it starts listening for incoming connections, with 'num_client' specifying the max number of queued clients
}

TCP *TcpServer::socket_accept()
{
  /* Note: do not delete the cxn in main */
  if (this->closed_) // if the server is closed, returns nullptr
  {
    logger_->log("TcpServer:socket_accept:Server is closed and cannot be started.");
    return nullptr;
  }

  // else
  TCP *clientTcp = TCP::socket_accept();
  if (clientTcp == nullptr)
  {
    this->logger_->log("TcpServer:socket_accept:Failed to accept a new connection.");
    return nullptr;
  }
  else
  {
    clientTcp->logger_ = this->logger_;  // associates the servers logger with the connected client. If this is not done, different log files will be created for each client, as each client (TCP object) has its own logger
    this->clients_.push_back(clientTcp); // adds the new connection to the 'clients_' vector
    this->logger_->log("TcpServer:socket_accept:New connection accepted.");

  } // TCP method | accpepts an incoming connection

  return clientTcp; // returns the new connection (TCP object)
}

StatusCode TcpServer::shutdown()
{
  if (this->closed_) // if the server is closed, returns -1
  {
    logger_->log("TcpServer:socket_accept:Server is closed and cannot be started.");
    return StatusCode::Error;
  }

  // else
  while (!this->clients_.empty())
  { // iterates through the 'clients_' vector and closes each client connection, then deletes the TCP object for each and removes it from the vector
    TCP *clientTcp = this->clients_.back();
    this->clients_.pop_back();
    if (clientTcp != nullptr)
    {
      clientTcp->TCP::socket_close(); // closes server side socket that is connected to the client
      delete clientTcp;
      clientTcp = nullptr;
    }
  }

  this->TCP::socket_close(); // closing server's listening socket
  this->closed_ = true;
  logger_->log("TcpServer:shutdown:Server has been shut down.");
  return StatusCode::Success; // once all clients are closed, the method returns 0
}

vector<TCP *> TcpServer::get_clients() const // returns a copy of the 'clients_' vector, which contains pointers to TCP objects represeting all the connected clients
{
  vector<TCP *> ret_vector(this->clients_);
  return ret_vector;
}

StatusCode TcpServer::broadcast(const string &message)
{
  if (this->closed_) // if the server is closed, returns -1
  {
    logger_->log("TcpServer:broadcast:Cannot broadcast on a closed server.");
    return StatusCode::Error;
  }

  bool partialErrorOccurred = false;
  logger_->log("TcpServer:broadcast:Attempting to broadcast message to all clients."); // logs the broadcast attempt and the message content
  for (auto &tcpClient : this->clients_)                                               // iterates over this->clients_
  {
    ssize_t send_length = tcpClient->socket_send_string(message);
    if (send_length != (unsigned int)message.length()) // if any message fails to send the complete length, 'retval' is set to 1 to indicate partial failure
    {
      partialErrorOccurred = true; // Indicates a partial error
      logger_->log("TcpServer:broadcast:Partial failure: Could not send the complete message to a client.");
    }
  }

  if (!partialErrorOccurred)
  {
    logger_->log("TcpServer:broadcast:Broadcast message sent to all clients.");
    return StatusCode::Success;
  }
  else
  {
    logger_->log("TcpServer:broadcast:Broadcast completed with partial errors.");
    return StatusCode::Partial_Error;
  }
}
