# 🛡️ TLS/SSL Handshake Simulation

This project simulates the TLS/SSL handshake process, showcasing secure communication between a client and server using both **DHE (Diffie-Hellman Ephemeral)** and **RSA** key exchange methods.

## 🔍 Overview

The project demonstrates the handshake steps in a secure SSL/TLS session, including:

- Client-server communication
- Certificate verification
- Key exchange
- Master secret derivation
- Secure session key generation
- Secure broadcast messaging

It is implemented at the socket level using C/C++ and logs detailed outputs to help visualize what happens behind the scenes during a handshake.

## ⚙️ Features

- ✅ **TLS Version 1.2** (version code 771)
- ✅ **Cipher Suite**: e.g., 0x0033 (DHE_RSA_WITH_AES_128_CBC_SHA)
- 🔁 Supports:
  - **DHE key exchange** with DH parameters `p` and `g`
  - **RSA key exchange** using server certificate
- 🔑 Derives:
  - Pre-master and master secret
  - Client/server write keys
  - Client/server IVs (initialization vectors)
- 🔐 Secure server broadcast after session is established
- 👥 Supports multiple clients

## 🖥️ Terminal Logs & Screenshots

### DHE Key Exchange

- `dhe-client1.png` – Client 1 log
- `dhe-client2.png` – Client 2 log
- `dhe-server-client1.png` – Server log (client 1)
- `dhe-server-client2.png` – Server log (client 2)
- `dhe-terminal.png` – Terminal showing successful connection and broadcast

### RSA Key Exchange

- `rsa-client1.png` – Client 1 log
- `rsa-client2.png` – Client 2 log
- `rsa-server-client1.png` – Server log (client 1)
- `rsa-server-client2.png` – Server log (client 2)
- `rsa-terminal.png` – Terminal showing successful RSA handshake

## 🔐 Handshake Steps (Simplified)

1. Client sends `ClientHello`
2. Server replies with `ServerHello` and certificate
3. Key exchange:
   - DHE: DH public key exchange
   - RSA: Encrypted pre-master secret
4. Master secret is derived
5. Client/server session keys and IVs are generated
6. Both send and verify `Finished` messages
7. Secure communication begins

## 🧪 Sample Output

```text
SSL Shared Data:
Chosen TLS version: 771
Chosen Cipher Suite: 51
Client Random: 4294967215
Server Random: 1983923769
DH Parameter p (Hex): FCD8E2A2015DA3911EE217750D2D386808B7EF018803EFD1761CC427...
DH Parameter g (Hex): 02
Pre-Master Secret (Hex): ef611c84a42ad61b4cb3fc6ead18b73caa139e308cd0720b61d2...
...
Client write key (Hex): 789c5f434faf5b4285ca451e13aa26b
