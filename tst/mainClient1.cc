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

    if (ssl_client->socket_connect(hostname, port, "DHE") != StatusCode::Success)
    {
        std::cerr << "\tc[" << c_idx << "]: couldn't connect" << std::endl;
        delete ssl_client;
        return 1;
    }

    // Send the first two messages.
    const char *messages[] = {
        "Client says hello",
        "Client asks how are you?"};
    for (int i = 0; i < 2; ++i)
    {
        if (ssl_client->socket_send_string(messages[i], nullptr) != StatusCode::Success)
        {
            std::cerr << "\tc[" << c_idx << "]: couldn't send" << std::endl;
            delete ssl_client;
            return 1;
        }
        std::cout << "\tc[" << c_idx << "]: sent" << std::endl;
    }

    // Wait to receive the broadcast message from the server.
    std::string recv_broadcast;
    if (ssl_client->socket_recv_string(&recv_broadcast, nullptr) != StatusCode::Success)
    {
        std::cerr << "\tc[" << c_idx << "]: couldn't receive broadcast" << std::endl;
        delete ssl_client;
        return 1;
    }
    std::cout << "\tc[" << c_idx << "]: received broadcast: '" << recv_broadcast << "'" << std::endl;

    // Send the third message.
    const char *third_message = "Client tries not to laugh";
    if (ssl_client->socket_send_string(third_message, nullptr) != StatusCode::Success)
    {
        std::cerr << "\tc[" << c_idx << "]: couldn't send" << std::endl;
        delete ssl_client;
        return 1;
    }
    std::cout << "\tc[" << c_idx << "]: sent" << std::endl;

    // Initiate key refresh.
    if (!ssl_client->handle_dhe())
    {
        std::cerr << "\tc[" << c_idx << "]: key refresh failed" << std::endl;
        delete ssl_client;
        return 1;
    }

    std::cout << "\tc[" << c_idx << "]: closed" << std::endl;
    delete ssl_client;

    std::cout << "\tc[" << c_idx << "]: exiting" << std::endl;

    return 0;
}
