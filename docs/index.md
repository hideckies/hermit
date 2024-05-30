# Home

<div style="margin: 72px 0; text-align: center;">
    <img src="assets/logo.png" width=300 height=300 />
</div>

## Hermit C2

Hermit is a command and control framework written in Go.

![demo](assets/demo/hermit_demo.gif)

## Features

- The C2 server and C2 client.
- gRPC server/client for operations.
- TLS for secure communication between the C2 server, client and agents.
- HTTPS listener.
- Multi-Staged Payload
- Data Encryption.
- Common Evasion Techniques
- Common Persistence Techniques
- Anti-Debug
- SQLite for saving data

![diagram](assets/diagram.png)

## Warning

This project can be used for educational purpose only.  
It's prohibited to use it on systems which is not under your control.

## Requirements

It's assumed that you operate both the C2 server and C2 client on **Linux**.

- Linux
- Go 1.21+
