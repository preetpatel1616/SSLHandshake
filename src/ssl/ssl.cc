#include "ssl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <iostream> // todo: remove this

#include <tcp.h>
#include "crypto_adaptor.h"

using namespace std;

SSL::SSL()
{
  this->tcp_ = new TCP();
  shared_key_ = NULL;
  shared_key_len_ = 0;
}

SSL::SSL(TCP *tcp)
{
  this->tcp_ = tcp;
  shared_key_ = NULL;
  shared_key_len_ = 0;
}

SSL::~SSL()
{ // destructor
  if (shared_key_ != NULL)
  { // frees the memory allocated for the shared key if it has been set
    free(shared_key_);
  }
  if (this->tcp_)
  { // closes the TCP connection if it exists and deleted the TCP object to avoid memory leaks
    this->tcp_->socket_close();
    delete this->tcp_;
  }
}

// hostname and port
string SSL::get_hostname() const
{ // retrieves the hostname from the associated TCP object
  string hostname;
  if (this->tcp_->get_hostname(&hostname) != 0)
  {
    printf("Can't get hostname.\n");
    exit(1);
  }
  return hostname;
}

int SSL::get_port() const
{ // retrieves the port number from the associated TCP object
  int port;
  if (this->tcp_->get_port(&port) != 0)
  {
    printf("Can't get port.\n");
    exit(1);
  }
  return port;
}

// set key
int SSL::set_shared_key(const unsigned char *const shared_key, size_t key_len)
{ // allocates memory for the sharek key and copies the key data into this newly allocated memory
  this->shared_key_len_ = key_len;
  this->shared_key_ = (unsigned char *)malloc(key_len * sizeof(unsigned char));
  memcpy(this->shared_key_, shared_key, key_len);
  return 0;
}

// strings: send, recv
// returns 0 on success, -1 otherwise

int SSL::send(const std::string &send_str)
{
  // make a record
  Record send_record;                  // makes an SSL record with
  send_record.hdr.type = REC_APP_DATA; // type set to REC_APP_DATA
  send_record.hdr.version = VER_99;    // and version set to VER_99

  // encrypt
  string cipher_text;

  if (aes_encrypt(this->shared_key_, this->shared_key_len_, // encrypts the provided string using an AES encryption function provided by the crypto_adaptor
                  &cipher_text, send_str) != 0)
  {
    cerr << "Couldn't encrypt." << endl;
    return -1;
  }

  // allocates memory for the encrypted data and copies it into the 'Record'
  char *data = (char *)malloc(cipher_text.length() * sizeof(char));
  memcpy(data, cipher_text.c_str(), cipher_text.length());
  send_record.data = data;

  // add length to record
  send_record.hdr.length = cipher_text.length();

  // send
  int ret_code;
  ret_code = send(send_record); // calls the 'send' function that takes a 'Record' object and sends the encrypted data
  free(send_record.data);       // frees the allocated memory for the data after sending

  return ret_code;
}

int SSL::recv(std::string *recv_str)
{
  Record recv_record; // makes an instance of SSl Record for the received record
  if (recv(&recv_record) == -1)
  {
    cerr << "Couldn't receive." << endl;
    return -1;
  }

  if (recv_record.hdr.type != REC_APP_DATA) // checks if the received record is of the type REC_APP_DATA
  {
    cerr << "Not app data." << endl;
    return -1;
  }

  // extract
  string cipher_text(recv_record.data, recv_record.hdr.length); // Extracts the encrypted data from the Record
  free(recv_record.data);

  // decrypt
  if (aes_decrypt(this->shared_key_, this->shared_key_len_, // Decrypts the data and stores the result in 'recv_str'
                  recv_str, cipher_text) != 0)
  {
    cerr << "Couldn't decrypt." << endl;
    return -1;
  }

  return 0;
}

// records: send, recv
// returns 0 on success, -1 otherwise

int SSL::send(const Record &send_record)
{
  if (this->tcp_ == NULL) // checks for valid TCP connection
  {
    cerr << "SSL::send: tcp not set." << endl;
    return -1;
  }

  // create new char array
  ssize_t send_len = 1 + 2 + 2 + send_record.hdr.length;
  char *send_str = (char *)malloc(send_len * sizeof(char)); // a new array (char* send_str) is dynamically allocated with a size equal to the calculated total length

  // fill it
  unsigned int index = 0;
  memcpy(&(send_str[index]), &send_record.hdr.type, 1);
  index += 1;
  memcpy(&(send_str[index]), &send_record.hdr.version, 2);
  index += 2;
  memcpy(&(send_str[index]), &send_record.hdr.length, 2);
  index += 2;
  memcpy(&(send_str[index]), send_record.data, send_record.hdr.length);

  // send it
  if (this->tcp_->socket_send(send_str, send_len) != send_len)
  {
    cerr << "SSL::send: couldn't send all data." << endl;
    return -1;
  }

  // clean up
  free(send_str);

  return 0;
}

int SSL::recv(Record *recv_record)
{
  if (this->tcp_ == NULL)
  {
    cerr << "SSL::recv: tcp not set." << endl;
    return -1;
  }

  // receive the header
  char *header = (char *)malloc(5 * sizeof(char));
  if (this->tcp_->socket_recv(header, 5) != 5)
  {
    cerr << "SSL::recv: Couldn't receive header." << endl;
    return -1;
  }

  char *type = header;
  char *version = &(header[1]);
  char *length = &(header[1 + 2]);

  uint16_t recv_len;
  memcpy(&recv_len, length, 2);
  char *recv_str = (char *)malloc(recv_len * sizeof(char));
  if (this->tcp_->socket_recv(recv_str, recv_len) != recv_len)
  {
    cerr << "SSL::recv: couldn't receive all data." << endl;
    return -1;
  }

  // set values to record
  memcpy(&(recv_record->hdr.type), type, 1);
  memcpy(&(recv_record->hdr.version), version, 2);
  recv_record->hdr.length = recv_len;
  recv_record->data = recv_str;

  // clean up
  free(header);

  return 0;
}

// Throughout the code, error handling is implemented using standard C++ streams (cerr) and control structures. The return values of -1 indicate an error in operations, and the use of exit(1) for unrecoverable errors causes the program to terminate immediately.