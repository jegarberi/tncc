# TNCC

A Go implementation of a TNCC (Terminal Network Connection Client) for interacting with Juniper VPN endpoints.

## Overview

This tool communicates with Juniper VPN hosts using a custom binary protocol, performing policy checks and retrieving authentication cookies (DSPREAUTH). It can operate in two modes:

1. **Direct mode**: One-time cookie retrieval
2. **Server mode**: Listens for commands via stdin or Unix socket

## Features

- Custom binary packet encoding/decoding (commands 0x0013, 0x0ce4, 0x0ce5, 0x0ce7)
- Zlib compression/decompression of message payloads
- Policy request and response handling
- Cookie management (DSPREAUTH, DSSIGNIN)
- Unix socket support (SOCK_SEQPACKET)
- Detailed logging with timestamps and source locations

## Usage

### Direct Mode

Retrieve a cookie directly:

```bash
./tncc <vpn_host> <DSPREAUTH> <DSSIGNIN>
```

### Server Mode

Run as a server listening on stdin:

```bash
./tncc <vpn_host>
```

#### Command Protocol

Commands are sent as text with the format:

```
<command>
key1=value1
key2=value2
```

Supported commands:

- `start`: Initiate cookie retrieval
  - Optional args: `Cookie`, `DSSIGNIN`
- `setcookie`: Set cookie (no response)

## Building

```bash
go build -o tncc tncc.go
```

## Using with OpenConnect

TNCC can be used with OpenConnect to connect to Juniper VPN servers that require Host Checker (TNCC) support.

### Basic Example

```bash
openconnect --protocol=nc vpn.example.com \
  --csd-wrapper=./tncc
```

### With Custom User and Options

```bash
openconnect --protocol=nc vpn.example.com \
  --user=your_username \
  --csd-wrapper=./tncc \
  --passwd-on-stdin
```

### How It Works

When OpenConnect encounters a Host Checker requirement:
1. OpenConnect invokes the TNCC binary with the VPN host as an argument
2. TNCC performs policy checks with the VPN server
3. TNCC retrieves the DSPREAUTH cookie
4. OpenConnect uses the cookie to complete the connection

The `--csd-wrapper` flag tells OpenConnect to use your TNCC binary instead of the built-in Java-based Host Checker.

## Security Notes

- Disables TLS certificate verification (`InsecureSkipVerify: true`)
- Uses 30-second HTTP timeout
- Supports Unix socket communication for IPC

## Protocol Details

The tool implements a custom binary protocol with nested packet structures:
- Outer packet (0x0013) contains inner packets
- Inner packet (0x0ce4) contains policy data
- Innermost packet (0x0ce7) contains compressed payload
- Payloads are zlib-compressed and base64-encoded

## License

See LICENSE file for details.
