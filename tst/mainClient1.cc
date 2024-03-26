#include <iostream>
#include <fstream>
#include <string>
#include "../src/ssl/SslClient.h"

int main()
{
    std::string serverIP;
    int serverPort;

    std::ifstream addrfile("address.txt");
    if (!addrfile.is_open())
    {
        std::cerr << "CLIENT: couldn't open address file" << std::endl;
        return 1;
    }

    addrfile >> serverIP >> serverPort;
    addrfile.close();

    SslClient client;
    if (client.socket_connect(serverIP, serverPort, "DHE") != StatusCode::Success)
    { // Adjust the key exchange algorithm as needed
        std::cerr << "CLIENT: Could not connect to server." << std::endl;
        return 1;
    }

    std::cout << "CLIENT: Connected with the server" << std::endl;
    const char *message = "Hello, server!";
    if (client.socket_send_string(std::string(message)) != StatusCode::Success)
    {
        std::cerr << "CLIENT: Failed to send message." << std::endl;
    }
    else
    {
        std::cout << "CLIENT: Message sent." << std::endl;
    }

    std::string response;
    if (client.socket_recv_string(&response) == StatusCode::Success)
    {
        std::cout << "CLIENT: Response from server: " << response << std::endl;
    }
    else
    {
        std::cerr << "CLIENT: Failed to receive response." << std::endl;
    }

    return 0;
}
