#include <iostream>
#include <fstream>
#include <unistd.h>
#include <openssl/provider.h>

#include "../src/ssl/SslServer.h" // Ensure this path is correct
#include "../src/ssl/SslClient.h" // Ensure this path is correct

void handle_client(SslClient *client)
{
    if (client != nullptr)
    {
        std::string recv_msg;
        StatusCode code = client->socket_recv_string(&recv_msg, client->tcp_);
        std::cout << "Server received: '" << recv_msg << "' with code: " << static_cast<int>(code) << std::endl;
        // Add handling for sending response to client here if necessary.
    }
}

int main()
{
    SslServer *server = new SslServer("tst/server_certificate.pem", "tst/server_private_key.pem");

    if (server->socket_listen() != StatusCode::Success)
    {
        std::cerr << "Couldn't start server" << std::endl;
        delete server;
        return 1;
    }

    std::string hostname = server->get_hostname();
    int port = server->get_port();
    std::cout << "Server's hostname " << hostname << " started on: " << port << std::endl;

    std::ofstream addrfile("address.txt");
    addrfile << hostname << std::endl
             << port;
    addrfile.close();

    // Handle clients sequentially
    for (int i = 0; i < 2; ++i) // Assuming you want to handle exactly 2 clients for this example.
    {
        std::cout << "Waiting for client " << i + 1 << std::endl;
        SslClient *client = server->socket_accept();
        if (client == nullptr)
        {
            std::cerr << "Error: couldn't accept client " << i + 1 << std::endl;
            continue;
        }
        std::cout << "Server accepted client " << i + 1 << std::endl;
        handle_client(client);
        // Consider deleting the client or properly closing its connection here
    }

    std::cout << "Server broadcasting..." << std::endl;
    if (server->broadcast("Server says 'HELLO ALL'") != StatusCode::Success)
    {
        std::cerr << "Error: couldn't broadcast" << std::endl;
    }

    std::cout << "Server shutting down..." << std::endl;
    if (server->shutdown() != StatusCode::Success)
    {
        std::cerr << "Error: couldn't shut down" << std::endl;
    }

    delete server;
    std::cout << "Server exiting..." << std::endl;

    return 0;
}
