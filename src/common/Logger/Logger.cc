#include "Logger.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

Logger::Logger(const std::string &log_filename) : logfile_(log_filename, std::ios::app) // initialize class members before the constructor's body is executed.
{

    if (!logfile_.is_open())
    {
        std::cerr << "Failed to open log file: " << log_filename << std::endl;
    }
}

Logger::~Logger()
{
    if (logfile_.is_open())
    {
        logfile_.close();
    }
}

// log msg prepended with current time
void Logger::log(const std::string &message)
{
    log_raw(getTimestamp() + ": " + message);
}

void Logger::log_raw(const std::string &message)
{
    log_raw(message.c_str(), message.length());
}

void Logger::log_raw(const char *message, size_t message_length)
{
    if (logfile_.is_open() && message_length > 0)
    {
        logfile_.write(message, message_length);
        logfile_ << std::endl;
    }
}

std::string Logger::getTimestamp() const
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X"); // X is for HH:MM:SS
    return ss.str();
}