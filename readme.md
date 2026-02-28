# RUDP -- Reliable Data Transfer over UDP

A custom application-layer protocol built on top of UDP that provides reliable, ordered file transfer with session management, integrity verification, encryption, and authentication.

**Authors:** Zach Benedict Hallare & Nathan Laborada

---

## Overview

RUDP implements reliability features on top of UDP for file transfer operations. The protocol operates in three phases:

1. **Session Establishment** -- Three-way handshake (SYN, SYN-ACK, ACK)
2. **Data Transfer** -- Stop-and-Wait ARQ with sequenced DATA/ACK packets
3. **Session Termination** -- FIN/FIN-ACK exchange

Both file **download** (server to client) and **upload** (client to server) are supported.

---

## Project Structure

```
UDP-Implementation/
  protocol.py        # Shared protocol definitions, packet format, crypto utilities
  server.py          # RUDP file transfer server
  client.py          # Interactive RUDP file transfer client
  rfc_document.md    # Full RFC-style protocol specification
  server_files/      # Directory the server reads from and writes to
```

---

## Requirements

- Python 3.6 or later
- No external dependencies (uses only the standard library)

---

## Getting Started

### 1. Start the Server

```bash
python server.py
```

The server binds to `127.0.0.1:12345` by default and serves files from the `server_files/` directory.

### 2. Start the Client

```bash
python client.py
```

The client presents an interactive prompt with the following commands:

| Command | Description |
|---|---|
| `download <filename>` | Download a file from the server's `server_files/` directory |
| `upload <filename>` | Upload a local file to the server |
| `exit` | Quit the client |

### Example Session

```
rudp> download test.txt
rudp> upload myfile.txt
rudp> exit
```

---

## Protocol Details

### Packet Format

Every packet on the wire follows this structure:

```
[13-byte Header] [Encrypted Payload (variable)] [32-byte HMAC-SHA256]
```

**Header fields (13 bytes total):**

| Field | Size | Description |
|---|---|---|
| `msg_type` | 1 byte | Packet type (SYN, ACK, DATA, FIN, etc.) |
| `session_id` | 4 bytes | Unique session identifier |
| `seq_num` | 4 bytes | Sequence number for ordering |
| `payload_len` | 2 bytes | Length of the encrypted payload |
| `checksum` | 2 bytes | CRC-16/CCITT-FALSE integrity check |

### Reliability

- **Stop-and-Wait ARQ** -- one packet sent at a time, waiting for ACK before proceeding
- **Timeout-based retransmission** -- packets are retransmitted after a configurable timeout (default 2 seconds)
- **Sequence numbering** -- data is reassembled in order regardless of arrival sequence
- **Maximum retries** -- transfers abort after 5 consecutive failed attempts

### Security

- **XOR Encryption** -- payloads are encrypted with a repeating-key XOR cipher using a shared secret
- **HMAC-SHA256 Authentication** -- a 32-byte HMAC digest is appended to every packet to prevent tampering and forgery
- **CRC-16 Checksum** -- header and payload integrity are verified using CRC-16/CCITT-FALSE

---

## Configuration

All protocol parameters are defined in `protocol.py`:

| Parameter | Default | Description |
|---|---|---|
| `SERVER_HOST` | `127.0.0.1` | Server listen address |
| `SERVER_PORT` | `12345` | Server listen port |
| `CHUNK_SIZE` | `1024` | Maximum payload bytes per DATA packet |
| `TIMEOUT` | `2.0` | Socket timeout in seconds |
| `MAX_RETRIES` | `5` | Maximum retransmission attempts |
| `SHARED_SECRET` | `rudp-secret-key-2025` | Shared key for encryption and HMAC |

---

## Testing Packet Loss

RUDP includes a built-in simulated packet loss mode for testing retransmission behavior without external tools.

To enable it, edit `protocol.py`:

```python
SIMULATE_LOSS    = True    # Enable simulated packet loss
LOSS_PROBABILITY = 0.3     # 30% chance of dropping each packet
```

Dropped packets are logged with a `[SIM]` prefix. The protocol will retransmit automatically, verifying that file transfers complete correctly even under loss.

---

## RFC Document

A full RFC-style specification is available in [rfc_document.md](rfc_document.md). It covers the protocol in detail, including state machines, swimlane diagrams, message type definitions, and error handling procedures.
