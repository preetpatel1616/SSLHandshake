#include <iostream>
#include <fstream>
#include <unistd.h>
#include <pthread.h>
#include <openssl/provider.h>

#include "../src/ssl/SslServer.h" // Ensure this path is correct
#include "../src/ssl/SslClient.h" // Ensure this path is correct

#define NUM_THREADS 2

void *handle_client(void *arg)
{

    SslClient *client = static_cast<SslClient *>(arg);
    if (client != nullptr)
    {
        std::string recv_msg;
        StatusCode code = client->socket_recv_string(&recv_msg);

        std::cout << "Server received: '" << recv_msg << "' with code: " << static_cast<int>(code) << std::endl;
    }

    pthread_exit(nullptr);
}

int main()
{

    if (!OSSL_PROVIDER_load(NULL, "default"))
    {
        fprintf(stderr, "Failed to load the default provider in server.\n");
        return 1;
    }
    SslServer *server = new SslServer("tst/server_certificate.pem", "tst/server_private_key.pem"); // Provide paths to your certificate and key

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

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        void *status;
        int rc = pthread_join(threads[i], &status);
        if (rc)
        {
            std::cerr << "Error: unable to join, " << rc << std::endl;
            delete server;
            exit(1);
        }
    }

    std::cout << "Server broadcasting..." << std::endl;

    if (server->broadcast("Server says 'HELLO ALL'") != StatusCode::Success)
    {
        std::cerr << "Error: couldn't broadcast" << std::endl;
        delete server;
        exit(1);
    }

    std::cout << "Server shutting down..." << std::endl;

    if (server->shutdown() != StatusCode::Success)
    {
        std::cerr << "Error: couldn't shut down" << std::endl;
        delete server;
        exit(1);
    }

    sleep(2);

    delete server;

    std::cout << "Server exiting..." << std::endl;

    return 0;
}
