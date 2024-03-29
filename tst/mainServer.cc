#include <iostream>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <openssl/provider.h>

#include "../src/ssl/SslServer.h" // Make sure this path is correct
#include "../src/ssl/SslClient.h" // Make sure this path is correct

#define NUM_THREADS 2
#define NUM_MESSAGES_PER_CLIENT 4 // Assuming you want to handle 4 messages per client before broadcasting

void *handle_client(void *arg)
{
    SslClient *client = static_cast<SslClient *>(arg);
    if (client != nullptr)
    {
        for (int i = 0; i < NUM_MESSAGES_PER_CLIENT; ++i)
        {
            std::string recv_msg;
            StatusCode code = client->socket_recv_string(&recv_msg, client->tcp_);
            std::cout << "Server received: '" << recv_msg << "' with code: " << static_cast<int>(code) << std::endl;
        }
    }
    pthread_exit(nullptr);
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

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        SslClient *client = server->socket_accept();
        if (client == nullptr)
        {
            std::cerr << "Error: couldn't accept" << std::endl;
            continue;
        }
        std::cout << "Server accepted client " << i + 1 << std::endl;
        int rc = pthread_create(&threads[i], nullptr, handle_client, static_cast<void *>(client));
        if (rc)
        {
            std::cerr << "Error: unable to create thread, " << rc << std::endl;
            delete server;
            exit(1);
        }
    }

    // Wait for threads to finish
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        void *status;
        pthread_join(threads[i], &status);
    }

    // After handling messages from clients, broadcast a message to all
    std::cout << "Server broadcasting..." << std::endl;
    server->broadcast("Server says 'HELLO ALL'");

    std::cout << "Server shutting down..." << std::endl;
    server->shutdown();
    delete server;
    std::cout << "Server exited successfully." << std::endl;

    return 0;
}
