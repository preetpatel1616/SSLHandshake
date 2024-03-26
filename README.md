# SSL Handshake Project

## Overview
This project implements a simplified SSL/TLS handshake mechanism for secure communication over a TCP/IP network. The implementation is divided into two main directories: `SSL` and `TCP`, each containing code files that encapsulate the functionalities of their respective layers.

## Directory Structure



## SSL Directory
The `SSL` directory contains the implementation of the SSL protocol, handling the encryption and decryption of data, managing SSL records, and performing the SSL handshake.

### Key Files
- **ssl.h**: Header file declaring the `SSL` class and associated structures for SSL records.
- **ssl.cc**: Implementation of the `SSL` class, providing methods for setting up the SSL context, sending and receiving SSL records, and managing the encryption keys.

## TCP Directory
The `TCP` directory houses the low-level TCP networking code that the SSL layer uses to transmit data.

### Key Files
- **tcp.h**: Header file for the `TCP` class, which offers TCP socket operations like listen, accept, connect, send, and receive.
- **tcp.cc**: Source file with the implementation of the `TCP` class methods.

## Getting Started
To get started with this project, clone the repository and explore the individual components within the `SSL` and `TCP` directories. The project is structured to follow the typical phases of an SSL/TLS handshake and secure communication.

### Prerequisites
List any prerequisites for the project here, including software versions, libraries, or tools that need to be installed.

### Building the Project
Provide instructions for building the project, including any `make` commands or build scripts.

```bash
# Example build command
make all

