#include "Utils.h"

#include <iomanip>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ctime>

#include <vector>
#include <stdexcept>
#include <sstream>

#include <vector>

using namespace std;

int get_publichostname(std::string *hostname)
{

  int fd;
  struct if_nameindex *curif, *ifs;
  struct ifreq req;
  char if_name_buff[20];
  char *ip_addr;
  char ip_addr_buff[18];

  if (hostname == NULL)
  {
    fprintf(stderr, "hostname is null");
    return -1;
  }

  if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
  {
    perror("socket");
    return -1;
  }

  ifs = if_nameindex();
  if (ifs == NULL)
  {
    perror("if_nameindex");
    return -1;
  }

  for (curif = ifs; curif && curif->if_name; curif++)
  {
    strncpy(req.ifr_name, curif->if_name, IFNAMSIZ);
    req.ifr_name[IFNAMSIZ] = 0;
    if (ioctl(fd, SIOCGIFADDR, &req) < 0)
    {
      // perror("ioctl");
      continue;
    }

    memset(if_name_buff, 0, 20);
    memset(ip_addr_buff, 0, 18);

    memcpy(if_name_buff, curif->if_name, strlen(curif->if_name));
    ip_addr = inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr);
    memcpy(ip_addr_buff, ip_addr, strlen(ip_addr));

    // skip the loopback and 192.x addresses
    *hostname = "undefined";
    if (strncmp(ip_addr_buff, "0.", 2) == 0)
    {
      continue;
    }
    else if (strncmp(ip_addr_buff, "127.", 4) == 0)
    {
      continue;
    }
    else if (strncmp(ip_addr_buff, "192.", 4) == 0)
    {
      continue;
    }
    else
    {
      *hostname = string(ip_addr_buff);
      break;
    }
  }

  if_freenameindex(ifs);
  if (close(fd) == -1)
  {
    perror("close");
    return -1;
  }

  return 0;
}

int get_datetime(std::string *datetime, const char *format)
{
  if (datetime == NULL || format == NULL)
  {
    return -1;
  }

  time_t t = time(0);
  struct tm *now = localtime(&t);
  char buf[80] = "";
  strftime(buf, sizeof(buf), format, now);

  *datetime = string(buf);
  return 0;
}

void append_uint32_to_vector(std::vector<uint8_t> &vec, uint32_t value)
{
  vec.push_back((value >> 24) & 0xFF);
  vec.push_back((value >> 16) & 0xFF);
  vec.push_back((value >> 8) & 0xFF);
  vec.push_back(value & 0xFF);
}

std::string toHexString(const std::vector<uint8_t> &bytes)
{
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (const auto &byte : bytes)
  {
    ss << std::setw(2) << static_cast<int>(byte);
  }
  return ss.str();
}

void prependLength(std::vector<uint8_t> &serializedData, const std::vector<uint8_t> &data)
{
  uint16_t length = data.size(); // Ensure that the size fits in a uint16_t
  // Convert length to bytes and insert at the beginning of the serializedData
  serializedData.push_back(static_cast<uint8_t>(length >> 8));   // High byte of length
  serializedData.push_back(static_cast<uint8_t>(length & 0xFF)); // Low byte of length
  // Insert the data itself
  serializedData.insert(serializedData.end(), data.begin(), data.end());
}

std::vector<uint8_t> readLengthPrefixedVector(const unsigned char *data, size_t &offset)
{
  uint16_t length = (data[offset] << 8) | data[offset + 1];        // Read length as 16-bit unsigned integer
  offset += 2;                                                     // Move past the length bytes
  std::vector<uint8_t> vec(data + offset, data + offset + length); // Extract the vector
  offset += length;                                                // Advance offset past the extracted data
  return vec;
}