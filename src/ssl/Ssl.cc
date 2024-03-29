#include "Ssl.h"
#include "../tcp/TCP.h"
#include "../common/Logger/Logger.h"
#include "crypto_adaptor.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <iostream> // todo: remove this

using namespace std;

// Record Types
const uint8_t Ssl::REC_CHANGE_CIPHER_SPEC = 0x14;
const uint8_t Ssl::REC_ALERT = 0x15;
const uint8_t Ssl::REC_HANDSHAKE = 0x16;
const uint8_t Ssl::REC_APP_DATA = 0x17;

// Record Version (TLS/SSL Version)

const uint16_t Ssl::TLS_1_0 = 0x0301; // 1.0
const uint16_t Ssl::TLS_1_1 = 0x0302; // 1.1
const uint16_t Ssl::TLS_1_2 = 0x0303; // 1.2

// Handshake Types: These are not necessarily 'types' of handshake, but more of like series of messages exchanged between client and server in a single handshake
const uint8_t Ssl::HS_CLIENT_HELLO = 0x01;
const uint8_t Ssl::HS_SERVER_HELLO = 0x02;
const uint8_t Ssl::HS_CERTIFICATE = 0x0B;
const uint8_t Ssl::HS_SERVER_KEY_EXCHANGE = 0x0C;
const uint8_t Ssl::HS_CERTIFICATE_REQUEST = 0x0D;
const uint8_t Ssl::HS_SERVER_HELLO_DONE = 0x0E;
const uint8_t Ssl::HS_CERTIFICATE_VERIFY = 0x0F;
const uint8_t Ssl::HS_CLIENT_KEY_EXCHANGE = 0x10;
const uint8_t Ssl::HS_FINISHED = 0x14;
const uint8_t Ssl::HS_KEYS_REFRESH = 0x07;

    // ciphersuites
    const uint16_t Ssl::TLS_DHE_RSA_WITH_AES_128_CBC_SHA_256 = 0x0033;
const uint16_t Ssl::TLS_RSA_WITH_AES_128_CBC_SHA_256 = 0x002F;

Ssl::Ssl()
{
  this->tcp_ = new TCP();
  this->logger_ = new Logger("ssl_default.log");
  this->logger_->log("Ssl:constructor:Ssl object created with default TCP connection.");
}

Ssl::Ssl(TCP *tcp)
{
  this->tcp_ = tcp;
  this->logger_ = tcp->logger_;
  this->logger_->log("Ssl:constructor:Ssl object created with provided TCP connection.");
}

Ssl::~Ssl()
{ // destructor
  if (this->tcp_ != nullptr)
  { // closes the TCP connection if it exists and deleted the TCP object to avoid memory leaks
    this->tcp_->socket_close();
    this->tcp_->logger_ = nullptr;
    delete this->tcp_;
    this->tcp_ = nullptr;
  }
  if (this->logger_)
  { // deleting logger object
    this->logger_->log("Ssl:deconstructor:Ssl object destroyed.");
    delete this->logger_;
    this->logger_ = nullptr;
  }
}

// 2. RecordHeader
struct RecordHeader // Metadata of the record like
{
  uint8_t record_type;  // record type
  uint16_t tls_version; // TLS version
  uint16_t data_size;   // size of the encrypted data
};

struct Record
{                   // Records are the basic units of data exchange in Ssl/TLS protocol
  RecordHeader hdr; // instant of RecordHeader structure
  char *data;       // actual data payload
};

// hostname and port
string Ssl::get_hostname() const
{ // retrieves the hostname from the associated TCP object
  string hostname;
  if (tcp_->get_hostname(&hostname) != 0)
  {
    logger_->log("Ssl:get_hostname:Cannot retrieve hostname.");
    exit(1);
  }
  return hostname;
}

int Ssl::get_port() const
{ // retrieves the port number from the associated TCP object
  int port;
  if (this->tcp_->get_port(&port) != StatusCode::Success)
  {
    logger_->log("Ssl:get_port:Cannot retrieve port.");
    exit(1);
  }
  return port;
}

// strings: send, recv
// returns 0 on success, -1 otherwise

StatusCode Ssl::socket_send_string(const std::string &send_string, std::vector<uint8_t> write_key, std::vector<uint8_t> write_Iv, TCP *tcpInstance)
{ // meant to be used after the handshake is established

  if (!tcp_)
  {
    logger_->log("Ssl:socket_send_string: Missing TCP connection");
    return StatusCode::Error;
  }

  // if(tcpInstance!=nullptr){
  //   tcp_=tcpInstance;
  // }

  // encrypt
  string encrypted_data;
  if (aes_encrypt(send_string, write_key, write_Iv, encrypted_data) != true)
  { // encrypts the provided string using an AES encryption function provided by the crypto_adaptor and stores it in cipher_text
    logger_->log("Ssl:socket_send_string: Encryption failed.");
    return StatusCode::Error;
  }

  // You allocate memory dynamically to store the encrypted string data (cipher_text). This is necessary because you're about to package this data into an Ssl Record, which expects a pointer to the data (char* data) rather than a std::string.
  char *data = (char *)malloc(encrypted_data.size());

  memcpy(data, encrypted_data.c_str(), encrypted_data.length()); // copies the bytes of ciphertext to the memory space to which the "data" is pointing

  // the reason we didnt directly use &cipher_text and instead copied the content of cipher_text to another location, and then passed its pointer
  // is because using &cipher_text directly, in this context, would typically mean taking the address of the std::string object itself, not the content it manages.
  // also the data should be of type char*

  // make a record
  Record send_record;
  send_record.hdr.record_type = REC_APP_DATA;
  send_record.hdr.tls_version = TLS_1_2;
  if (send_record.hdr.record_type == REC_APP_DATA)
  {
    send_record.hdr.data_size = encrypted_data.size() + 1; // for null terminator
  }
  else
    send_record.hdr.data_size = encrypted_data.size(); // and version set to VER_99

  // Allocate memory for data and copy payload into it
  send_record.data = new char[send_record.hdr.data_size];
  memcpy(send_record.data, data, send_record.hdr.data_size); // Copy the data as it is
  send_record.data[send_record.hdr.data_size] = '\0';        // Manually add the null terminator at the end

  // send
  StatusCode status = socket_send_record(send_record, tcpInstance); // calls the 'send' function that takes a 'Record' object and sends the encrypted data
  delete[] send_record.data;                                        // After sending the Record, you free the memory allocated for the data to prevent memory leaks. This is an essential step since you allocated memory dynamically for data.

  return status;
}

StatusCode Ssl::socket_recv_string(std::string *recv_string, std::vector<uint8_t> write_key, std::vector<uint8_t> write_Iv, TCP *tcpInstance)
{
  if (!tcp_)
  {
    logger_->log("Ssl:socket_recv_string: Missing TCP connection.");
    return StatusCode::Error;
  }

  // convert the received buffer into record and store it
  Record recv_record;
  StatusCode status = socket_recv_record(&recv_record, tcpInstance);
  if (status != StatusCode::Success)
  {
    logger_->log("Ssl:socket_recv_string:Failed to receive record.");
    return status;
  }

  if (recv_record.hdr.record_type != REC_APP_DATA)
  {
    logger_->log("Ssl:socket_recv_string: Received record is not application data.");
    delete[] recv_record.data;
    return StatusCode::Error;
  }

  // Convert the received data into a vector<uint8_t> for decryption
  std::string encrypted_data;

  // decrypt the received data
  std::string decrypted_data;
  if (aes_decrypt(encrypted_data, write_key, write_Iv, decrypted_data) != true)
  {
    logger_->log("Ssl:socket_recv_string: Decryption failed.");
    return StatusCode::Error;
  }
  // Assign the decrypted text to the output string
  *recv_string = decrypted_data;

  logger_->log("Ssl:socket_recv_string: Message received and decrypted successfully.");
  return StatusCode::Success;
}

// records: send, recv
// returns 0 on success, -1 otherwise

StatusCode Ssl::socket_send_record(const Record &send_record, TCP *tcpInstance)
{
  if (!tcp_)
  {
    logger_->log("Ssl:socket_send_record: Missing TCP connection.");
    return StatusCode::Error;
  }

  if (tcpInstance == nullptr)
  {
    tcpInstance = tcp_;
  }

  // create new char array
  ssize_t buffer_length = 1 + 2 + 2 + send_record.hdr.data_size;
  char *buffer = (char *)malloc(buffer_length * sizeof(char));

  // fill it
  unsigned int index = 0;
  memcpy(&(buffer[index]), &send_record.hdr.record_type, 1);
  index += 1;
  memcpy(&(buffer[index]), &send_record.hdr.tls_version, 2);
  index += 2;
  memcpy(&(buffer[index]), &send_record.hdr.data_size, 2);
  index += 2;
  memcpy(&(buffer[index]), send_record.data, send_record.hdr.data_size);

  // Send the serialized record using the underlying TCP connection
  if (tcpInstance->socket_send_buffer(buffer, buffer_length) != buffer_length)
  {
    logger_->log("Ssl:socket_send_record:Failed to send the record.");
    return StatusCode::Error;
  }

  logger_->log("Ssl:socket_send_record:Record sent successfully.");
  return StatusCode::Success;
}

StatusCode Ssl::socket_recv_record(Record *recv_record, TCP *tcpInstance)
{
  if (!tcp_)
  {
    logger_->log("Ssl:socket_recv_record: Missing TCP connection.");
    return StatusCode::Error;
  }
  if (tcpInstance == nullptr)
  {
    tcpInstance = tcp_;
  }

  // receiving header

  char *header = (char *)malloc(5 * sizeof(char));
  if (tcpInstance->socket_recv_buffer(header, 5) != 5)
  {
    this->logger_->log("Ssl::socket_recv_record: Couldn't receive header.");
    return StatusCode::Error;
  }
  char *record_type = header;
  char *tls_version = &(header[1]);
  char *data_size = &(header[1 + 2]);

  uint16_t received_record_buffer_length;
  memcpy(&received_record_buffer_length, data_size, 2);
  char *received_record_buffer = (char *)malloc(received_record_buffer_length * sizeof(char));

  if (tcpInstance->socket_recv_buffer(received_record_buffer, received_record_buffer_length) != received_record_buffer_length)
  {
    logger_->log("Ssl::socket_recv_record: Failed to receive the record buffer.");
    return StatusCode::Error;
  }
  // Deserializing the buffer into a Record object
  memcpy(&(recv_record->hdr.record_type), record_type, 1);
  memcpy(&(recv_record->hdr.tls_version), tls_version, 2);
  recv_record->hdr.data_size = received_record_buffer_length;
  recv_record->data = received_record_buffer;

  free(header);
  logger_->log("Ssl:socket_recv_record: Record received successfully.");
  return StatusCode::Success;
}

// Throughout the code, error handling is implemented using standard C++ streams (cerr) and control structures. The return values of -1 indicate an error in operations, and the use of exit(1) for unrecoverable errors causes the program to terminate immediately.