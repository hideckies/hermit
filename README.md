# Hermit C2

Command and Control Framework. 
I'm developing this for my learning purpose.

![demo](assets/hermit_demo.gif)

<br />

## Features

- The C2 server and C2 client.
- gRPC server/client for operations.
- TLS for secure communication between the C2 server, client and agents.
- HTTPS listener.
- Multi staged payloads.
- SQLite for the data persistence.

<br />

## Warning

- This project can be used for educational purpose only. It's prohibited to use it on systems which is not under your control.
- I'm a crypto amateur so I cannot guarantee that the implementation of the encryption is not vulnerable.

<br />

## Requirements

It's assumed that you operate both the C2 server and C2 client on **Linux**.

- Linux
- Go 1.21+

<br />

## Getting Started

Please see [the docs](https://hermit.hdks.org/getting-started/).  
[Tutorials](https://hermit.hdks.org/tutorials/simple-implant-beacon/) are also available.  
