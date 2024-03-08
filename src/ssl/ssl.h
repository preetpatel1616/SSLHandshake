#ifndef SSL_H
#define SSL_H

#include <stdint.h>

#include <string>

class TCP;
class Logger;

class SSL
{
  // some types and constants
public:
  //////////////////////////////////////////////
  // SSL Record

  struct RecordHeader
  {                   // Metadata of the record like,
    uint8_t type;     // record type
    uint16_t version; // version
    uint16_t length;  // length
  };

  struct Record
  {                   // Records are the basic units of data exchange in SSL/TLS protocol
    RecordHeader hdr; // instant of RecordHeader structure
    char *data;       // actual data payload
  };

  // Record Types
  static const uint8_t REC_CHANGE_CIPHER_SPEC = 0x14;
  static const uint8_t REC_ALERT = 0x15;
  static const uint8_t REC_HANDSHAKE = 0x16;
  static const uint8_t REC_APP_DATA = 0x17;

  // Record Version
  static const uint16_t VER_99 = 0x0909;

  // Handshake Types: These are not necessarily 'types' of handshake, but more of like series of messages exchanged between client and server in a single handshake
  static const uint8_t HS_HELLO_REQUEST = 0x00;
  static const uint8_t HS_CLIENT_HELLO = 0x01;
  static const uint8_t HS_SERVER_HELLO = 0x02;
  static const uint8_t HS_CERTIFICATE = 0x0B;
  static const uint8_t HS_SERVER_KEY_EXCHANGE = 0x0C;
  static const uint8_t HS_CERTIFICATE_REQUEST = 0x0D;
  static const uint8_t HS_SERVER_HELLO_DONE = 0x0E;
  static const uint8_t HS_CERTIFICATE_VERIFY = 0x0F;
  static const uint8_t HS_CLIENT_KEY_EXCHANGE = 0x10;
  static const uint8_t HS_FINISHED = 0x14;

  // KeyExchange Types
  static const uint16_t KE_DHE = 0x0000;
  static const uint16_t KE_DH = 0x0001;
  static const uint16_t KE_RSA = 0x0002;

  //////////////////////////////////////////////
  // ssl functions
public:
  SSL();
  SSL(TCP *tcp);
  virtual ~SSL();

  std::string get_hostname() const;
  int get_port() const;

  // For sending and receiving raw string data (application data)
  virtual int send(const std::string &send_str);
  virtual int recv(std::string *recv_str);

  // For sending and receiving SSL Records
  virtual int send(const Record &send_record);
  virtual int recv(Record *recv_record);

  // In summary, send(const std::string &send_str) is likely intended for use when you have plain text
  // that needs to be encrypted and sent as application data, while send(const Record &send_record) is for
  // when you have an SSL record ready to go, which may be the case for other parts of the SSL protocol, like handshake messages.

  // for key
  virtual int set_shared_key(const unsigned char *const shared_key, size_t key_len);

protected:
  TCP *tcp_;                  // a pointer to a TCP object
  Logger *logger_;            // a pointer to a Logger object
  unsigned char *shared_key_; // a pointer to shared_key_ array
  size_t shared_key_len_;     // its length
};

#endif // SSL_H