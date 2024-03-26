#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>

class Logger
{
public:
    Logger(const std::string &log_filename);
    ~Logger();

    void log(const std::string &message);
    void log_raw(const std::string &message);
    void log_raw(const char *message, size_t message_length);

private:
    std::ofstream logfile_;
    std::string getTimestamp() const;
};

#endif // LOGGER_H