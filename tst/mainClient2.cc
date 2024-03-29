#include <iostream>
#include <fstream>
#include <string>
#include "../src/ssl/SslClient.h" // Make sure this path is correct

int main(int argc, char *argv[])
{
    std::string c_idx = "0";
    if (argc > 1)
    {
        c_idx = std::string(argv[1]);
    }

    std::string hostname;
    int port;

    std::ifstream addrfile("address.txt");
    if (!addrfile.is_open())
    {
        std::cerr << "\tc[" << c_idx << "]: couldn't open address file" << std::endl;
        return 1;
    }

    addrfile >> hostname >> port;
    addrfile.close();

    SslClient *ssl_client = new SslClient();

    if (ssl_client->socket_connect(hostname, port, "RSA") != StatusCode::Success)
    { // KE_DHE constant depends on your implementation
        std::cerr << "\tc[" << c_idx << "]: couldn't connect" << std::endl;
        delete ssl_client;
        return 1;
    }

    std::cout << "\tc[" << c_idx << "]: connected" << std::endl;

    if (ssl_client->socket_send_string("client says hello", nullptr) != StatusCode::Success)
    {
        std::cerr << "\tc[" << c_idx << "]: couldn't send" << std::endl;
        delete ssl_client;
        return 1;
    }

    std::cout << "\tc[" << c_idx << "]: sent" << std::endl;

    std::string recv_buff;
    if (ssl_client->socket_recv_string(&recv_buff, nullptr) != StatusCode::Success)
    {
        std::cerr << "\tc[" << c_idx << "]: couldn't receive" << std::endl;
        delete ssl_client;
        return 1;
    }

    std::cout << "\tc[" << c_idx << "]: received '" << recv_buff << "'" << std::endl;

    // if (ssl_client->socket_close() != StatusCode::Success)
    // {
    //   std::cerr << "\tc[" << c_idx << "]: couldn't close" << std::endl;
    //   delete ssl_client;
    //   return 1;
    // }

    std::cout << "\tc[" << c_idx << "]: closed" << std::endl;

    delete ssl_client;

    std::cout << "\tc[" << c_idx << "]: exiting" << std::endl;

    return 0;
}