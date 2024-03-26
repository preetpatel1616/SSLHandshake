#include <string>
#include <vector>

int get_publichostname(std::string *hostname);

int get_datetime(std::string *datetime, const char* format);

void append_uint32_to_vector(std::vector<uint8_t> &vec, uint32_t value);
