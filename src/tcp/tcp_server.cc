#include "tcp_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <iostream>
#include <fstream>

#include "logger.h"
#include "utils.h"

using namespace std;

TcpServer::TcpServer()
{ // Constructor: Initializes the TcpServer object and sets up a logger to log server activity
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0)
  {
    exit(1);
  }
  set_logger(new Logger("server_" + datetime + ".log")); // The logger filename includes the current date and time

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Server Log at " + datetime);

  this->closed_ = false; // indicating the server is open to start and accept connections
}

TcpServer::~TcpServer()
{ // Destructor
  if (!this->closed_)
  { // Closes any active connections
    this->shutdown();
  }
  if (this->logger_)
  { // Deletes the logger object and sets the logger pointer to NULL
    delete this->logger_;
    set_logger(NULL);
  }
}

int TcpServer::start(int num_client)
{
  if (this->closed_) // if the server is closed, returns -1
  { 
    return -1;
  }

  return socket_listen(num_client); // TCP method | If the server is open, then it starts listening for incoming connections, with 'num_client' specifying the max number of queued clients
}

TCP *TcpServer::accept()
{
  /* Note: do not delete the cxn in main */
  if (this->closed_) // if the server is closed, returns NULL
  {              
    return NULL; 
  }

  // else
  TCP *cxn = socket_accept();          // TCP method | accpepts an incoming connection
  cxn->set_logger(this->get_logger()); // associates the same logger with the new connection, meaning that all logging from client connections will be directed to the same log file that the server uses
  this->clients_.push_back(cxn);       // adds the new connection to the 'clients_' vector
  return cxn;                          // returns the new connection (TCP object)
}

int TcpServer::shutdown()
{
  if (this->closed_) // if the server is closed, returns -1
  {            
    return -1; 
  }

  // else
  while (!this->clients_.empty())
  { // iterates through the 'clients_' vector and closes each client connection, then deletes the TCP object for each and removes it from the vector
    TCP *cxn = this->clients_.back();
    this->clients_.pop_back();
    if (cxn != NULL)
    {
      cxn->socket_close();
      delete cxn;
    }
  }

  return 0; // once all clients are closed, the method returns 0
}

vector<TCP *> TcpServer::get_clients() const // returns a copy of the 'clients_' vector, which contains pointers to TCP objects represeting all the connected clients
{
  vector<TCP *> ret_vector(this->clients_);
  return ret_vector;
}

int TcpServer::broadcast(const string &msg)
{
  if (this->closed_) //if the server is closed, returns -1
  {
    return -1;
  }

  int retval = 0;

  this->logger_->log("broadcast:"); //logs the broadcast attempt and the message content
  this->logger_->log_raw(msg);

  for (vector<TCP *>::iterator it = this->clients_.begin(); // iterates over the 'clients_' and sends the message, 'msg' to each connected client using their respective 'socket_send' method
       it != this->clients_.end(); ++it)
  {
    ssize_t send_len;
    send_len = (*it)->socket_send(msg);
    if (send_len != (unsigned int)msg.length()) // if any message fails to send the complete length, 'retval' is set to 1 to indicate partial failure
    {
      retval = 1;
    }
  }

  return retval;
}
