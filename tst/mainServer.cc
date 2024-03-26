#include <iostream>
#include <fstream>
#include <signal.h>
#include <unistd.h>
#include "../src/ssl/SslServer.h"
#include "../src/ssl/SslClient.h"

// Signal handling for graceful shutdown
volatile sig_atomic_t keepRunning = 1;

void intHandler(int dummy)
{
    keepRunning = 0;
}

int main()
{
    signal(SIGINT, intHandler);

    SslServer *server = new SslServer("tst/server_certificate.pem", "tst/server_private_key.pem");

    if (server->socket_listen(5) != StatusCode::Success)
    {
        std::cerr << "Couldn't start server" << std::endl;
        delete server;
        return 1;
    }

    std::string hostname = server->get_hostname();
    int port = server->get_port();
    std::cout << "Server started on: " << hostname << ":" << port << std::endl;

    std::ofstream addrfile("address.txt");
    addrfile << hostname << std::endl
             << port;
    addrfile.close();

    SslClient *client = server->socket_accept();

    if (client == nullptr)
    {
        std::cerr << "Error: couldn't accept client" << std::endl;
        delete server;
        return 1;
    }

    std::cout << "Server accepted a client" << std::endl;

    std::string recv_msg;
    StatusCode code = client->socket_recv_string(&recv_msg);
    if (code == StatusCode::Success)
    {
        std::cout << "Server received: '" << recv_msg << "'" << std::endl;
        server->broadcast("Server says 'HELLO ALL'");
    }
    else
    {
        std::cerr << "Failed to receive message from client" << std::endl;
    }

    std::cout << "Server shutting down..." << std::endl;
    delete server;
    std::cout << "Server exited gracefully" << std::endl;
    return 0;
}
