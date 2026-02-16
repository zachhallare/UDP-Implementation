# RUDP – Reliable Data Transfer over UDP

## RFC-Style Protocol Specification

**Document Title:** RUDP File Transfer Protocol Specification  
**Version:** 1.0  
**Date:** February 2025  
**Authors:** Zach Hallare  

---

## 1. Introduction

This document specifies the **Reliable UDP (RUDP) File Transfer Protocol**, a custom application-layer protocol built on top of the User Datagram Protocol (UDP). RUDP provides reliable, ordered data delivery and session management for file transfer operations (upload and download), replicating key features of TCP at the application layer.

### 1.1 Motivation

UDP offers connectionless, best-effort delivery with minimal overhead. However, it does not guarantee reliable delivery, ordered delivery, congestion control, or session management. Many Internet protocols (DHCP, DNS, TFTP, NTP) intentionally use UDP and implement their own control mechanisms.

RUDP demonstrates how reliability and ordering can be achieved at the application layer using:
- Session establishment via a three-way handshake
- Sequenced data packets
- Acknowledgement-based flow control (Stop-and-Wait ARQ)
- Timeout-based retransmission
- Clean session termination via FIN/FIN-ACK exchange
- CRC-16 checksum for integrity verification

### 1.2 Terminology

The key words "MUST", "SHOULD", "MAY", and "MUST NOT" in this document are to be interpreted as described in RFC 2119.

- **Client**: The endpoint that initiates a session and requests file operations.
- **Server**: The endpoint that listens for incoming sessions and serves or receives files.
- **Session**: A logical connection identified by a unique `session_id`.
- **Packet**: A single RUDP message consisting of a header and optional payload.

---

## 2. Protocol Overview

RUDP operates in three phases:

1. **Session Establishment** – Three-way handshake (SYN → SYN-ACK → ACK)
2. **Data Transfer** – Stop-and-Wait ARQ with sequenced DATA/ACK packets
3. **Session Termination** – FIN → FIN-ACK exchange

### 2.1 Swimlane Diagram – File Download

```
    Client                                Server
      │                                     │
      │──── SYN (DOWNLOAD:file.txt) ───────>│
      │                                     │
      │<──── SYN-ACK (session params) ──────│
      │                                     │
      │──── ACK ───────────────────────────>│
      │                                     │
      │           ═══ HANDSHAKE COMPLETE ═══│
      │                                     │
      │<──── DATA seq=0 (chunk 1) ─────────│
      │──── ACK seq=0 ────────────────────>│
      │                                     │
      │<──── DATA seq=1 (chunk 2) ─────────│
      │──── ACK seq=1 ────────────────────>│
      │                                     │
      │              ... (repeats) ...      │
      │                                     │
      │<──── DATA seq=N (empty = EOF) ─────│
      │──── ACK seq=N ────────────────────>│
      │                                     │
      │           ═══ TRANSFER COMPLETE ═══ │
      │                                     │
      │──── FIN ───────────────────────────>│
      │<──── FIN-ACK ──────────────────────│
      │                                     │
      │         ═══ SESSION TERMINATED ═══  │
```

### 2.2 Swimlane Diagram – File Upload

```
    Client                                Server
      │                                     │
      │──── SYN (UPLOAD:file.txt) ─────────>│
      │                                     │
      │<──── SYN-ACK (session params) ──────│
      │                                     │
      │──── ACK ───────────────────────────>│
      │                                     │
      │           ═══ HANDSHAKE COMPLETE ═══│
      │                                     │
      │──── DATA seq=0 (chunk 1) ──────────>│
      │<──── ACK seq=0 ────────────────────│
      │                                     │
      │──── DATA seq=1 (chunk 2) ──────────>│
      │<──── ACK seq=1 ────────────────────│
      │                                     │
      │              ... (repeats) ...      │
      │                                     │
      │──── DATA seq=N (empty = EOF) ──────>│
      │<──── ACK seq=N ────────────────────│
      │                                     │
      │           ═══ TRANSFER COMPLETE ═══ │
      │                                     │
      │──── FIN ───────────────────────────>│
      │<──── FIN-ACK ──────────────────────│
      │                                     │
      │         ═══ SESSION TERMINATED ═══  │
```

### 2.3 Swimlane Diagram – Retransmission on Timeout

```
    Client                                Server
      │                                     │
      │<──── DATA seq=2 ──────────────────── │
      │                                      │
      │     (ACK lost / timeout)             │
      │                                      │
      │<──── DATA seq=2 (retransmit) ─────── │  ← Server retransmits
      │──── ACK seq=2 ─────────────────────>│
      │                                     │
```

### 2.4 Swimlane Diagram – File Not Found Error

```
    Client                                Server
      │                                     │
      │──── SYN (DOWNLOAD:missing.txt) ────>│
      │                                     │
      │<──── SYN-ACK ──────────────────────│
      │                                     │
      │──── ACK ───────────────────────────>│
      │                                     │
      │<──── ERROR ("File not found") ─────│
      │                                     │
      │──── FIN ───────────────────────────>│
      │<──── FIN-ACK ──────────────────────│
```

---

## 3. Packet Message Format

Every RUDP packet consists of a **13-byte fixed header** followed by an **optional variable-length payload**.

### 3.1 Header Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   msg_type    |                  session_id                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           (cont.)     |                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          seq_num                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          payload_len          |           checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       payload (variable)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Field Descriptions

| Field | Size | Encoding | Description |
|---|---|---|---|
| `msg_type` | 1 byte | Unsigned integer (big-endian) | Identifies the packet type (see §3.3) |
| `session_id` | 4 bytes | Unsigned 32-bit integer (big-endian) | Unique session identifier assigned by the server |
| `seq_num` | 4 bytes | Unsigned 32-bit integer (big-endian) | Sequence number for ordering and acknowledgement |
| `payload_len` | 2 bytes | Unsigned 16-bit integer (big-endian) | Length of the payload in bytes (0–65535) |
| `checksum` | 2 bytes | Unsigned 16-bit integer (big-endian) | CRC-16/CCITT-FALSE over the entire packet (checksum field zeroed during computation) |

**Binary encoding:** The header uses network byte order (big-endian) via Python's `struct` format string `"!BIIHH"`.

### 3.3 Message Types

| Value | Name | Description |
|---|---|---|
| 0 | `SYN` | Session initiation request from the client |
| 1 | `SYN-ACK` | Server acknowledgement of session establishment |
| 2 | `ACK` | Acknowledgement of a received packet |
| 3 | `DATA` | Data payload carrying file content |
| 4 | `FIN` | Session termination request |
| 5 | `FIN-ACK` | Acknowledgement of session termination |
| 6 | `ERROR` | Error notification (payload contains error message) |

### 3.4 Payload Conventions

- **SYN** payload: UTF-8 encoded command string, e.g., `"DOWNLOAD:filename.txt"` or `"UPLOAD:filename.txt"`
- **SYN-ACK** payload: UTF-8 encoded session parameters, e.g., `"SESSION:12345|CHUNK:1024|OP:DOWNLOAD"`
- **ACK** payload: Empty (0 bytes)
- **DATA** payload: Raw binary file data (up to `CHUNK_SIZE` bytes). An empty DATA payload (0 bytes) signals End-of-File.
- **FIN** / **FIN-ACK** payload: Empty (0 bytes)
- **ERROR** payload: UTF-8 encoded error message string

---

## 4. State Machines

### 4.1 Client State Machine

```
                   ┌────────────────┐
                   │  DISCONNECTED  │
                   └───────┬────────┘
                           │ User issues command
                           │ Send SYN
                           ▼
                   ┌────────────────┐
              ┌────│    SYN_SENT    │────┐
              │    └───────┬────────┘    │
    Timeout + │            │ Recv        │ MAX_RETRIES
    retransmit│            │ SYN-ACK     │ exceeded
              │            │ Send ACK    │
              └────>       ▼             │
                   ┌────────────────┐    │
                   │  ESTABLISHED   │    │
                   └───────┬────────┘    │
                           │ Begin       │
                           │ transfer    │
                           ▼             │
                   ┌────────────────┐    │
              ┌────│  TRANSFERRING  │    │
              │    └───────┬────────┘    │
    Timeout + │            │ Transfer    │
    retransmit│            │ complete    │
              │            │ Send FIN    │
              └────>       ▼             │
                   ┌────────────────┐    │
              ┌────│   FIN_SENT     │    │
              │    └───────┬────────┘    │
    Timeout + │            │ Recv        │
    retransmit│            │ FIN-ACK     │
              └────>       ▼             ▼
                   ┌────────────────┐
                   │  DISCONNECTED  │
                   └────────────────┘
```

### 4.2 Server State Machine

```
                   ┌────────────────┐
                   │     IDLE       │◄───────────────────┐
                   └───────┬────────┘                    │
                           │ Recv SYN                    │
                           │ Generate session_id         │
                           │ Send SYN-ACK                │
                           ▼                             │
                   ┌────────────────┐                    │
              ┌────│  SYN_RECEIVED  │                    │
              │    └───────┬────────┘                    │
    Timeout + │            │ Recv ACK                    │
    resend    │            │ (handshake                  │
    SYN-ACK   │            │  complete)                  │
              └────>       ▼                             │
                   ┌────────────────┐                    │
                   │  ESTABLISHED   │                    │
                   └───────┬────────┘                    │
                           │ Begin                       │
                           │ transfer                    │
                           ▼                             │
                   ┌────────────────┐                    │
              ┌────│  TRANSFERRING  │                    │
              │    └───────┬────────┘                    │
    Timeout + │            │ Transfer                    │
    retransmit│            │ complete                    │
              └────>       ▼                             │
                   ┌────────────────┐                    │
                   │  WAIT_FOR_FIN  │                    │
                   └───────┬────────┘                    │
                           │ Recv FIN                    │
                           │ Send FIN-ACK                │
                           └────────────────────────────>┘
```

---

## 5. Reliability Mechanisms

### 5.1 Stop-and-Wait ARQ

RUDP employs **Stop-and-Wait Automatic Repeat reQuest (ARQ)** for reliable data transfer:

1. The sender MUST transmit one DATA packet and wait for an ACK before sending the next.
2. Each DATA packet MUST carry a unique, monotonically increasing sequence number.
3. The receiver MUST respond with an ACK containing the sequence number of the received DATA packet.
4. Duplicate DATA packets (same sequence number) SHOULD be accepted but not double-processed; the receiver MUST re-send the ACK.

### 5.2 Timeout and Retransmission

- The sender MUST set a socket timeout of `TIMEOUT` seconds (default: 2.0s) when waiting for a response.
- If no response is received within the timeout, the sender MUST retransmit the packet.
- If `MAX_RETRIES` consecutive timeouts occur (default: 5), the sender MUST abort the operation and report an error.

### 5.3 Sequencing and Ordering

- DATA packets MUST be assigned monotonically increasing sequence numbers starting from 0.
- The receiver MUST store received data indexed by sequence number.
- Upon receiving the EOF signal, the receiver MUST reassemble the complete file by concatenating payloads in ascending sequence-number order.
- This ensures correct ordering even if packets arrive out of order.

### 5.4 Checksum Verification (CRC-16)

- Every packet MUST include a CRC-16/CCITT-FALSE checksum in the header.
- The checksum is computed over the entire packet with the checksum field set to zero.
- The receiver MUST verify the checksum upon receipt. Packets with invalid checksums MUST be silently discarded.

---

## 6. Error Handling

### 6.1 Timeout – Unresponsive Peer

- If a peer does not respond within `TIMEOUT` seconds, the packet MUST be retransmitted.
- After `MAX_RETRIES` consecutive failures, the session MUST be terminated with an error message logged.

### 6.2 File Not Found

- If the server receives a `DOWNLOAD` request for a file that does not exist, it MUST respond with an `ERROR` packet containing the message `"File not found: <filename>"`.
- The client MUST display the error message and proceed to session termination.

### 6.3 Session Mismatch

- If a packet is received with a `session_id` that does not match the current active session, it MUST be silently discarded.
- This prevents interference from stale or misrouted packets.

### 6.4 Malformed Packets

- Packets shorter than `HEADER_SIZE` (13 bytes) MUST be discarded.
- Packets where `payload_len` does not match the actual payload size MUST be discarded.

---

## 7. File Transfer Operations

### 7.1 Download (Server → Client)

1. Client sends `SYN` with payload `"DOWNLOAD:<filename>"`.
2. Server validates the file exists and responds with `SYN-ACK`.
3. After handshake completion (ACK received), the server reads the file and sends it as a sequence of `DATA` packets.
4. Each DATA packet carries up to `CHUNK_SIZE` bytes (default: 1024).
5. Client sends `ACK` for each DATA packet.
6. Transfer is binary-safe: file data is transmitted as raw bytes with no encoding transformation.

### 7.2 Upload (Client → Server)

1. Client sends `SYN` with payload `"UPLOAD:<filename>"`.
2. Server responds with `SYN-ACK`, preparing to receive the file.
3. After handshake completion, the client reads the local file and sends it as sequenced `DATA` packets.
4. Server sends `ACK` for each DATA packet and stores payloads indexed by sequence number.
5. Upon receiving the EOF signal, the server reassembles and writes the file to disk.
6. Transfer is binary-safe.

---

## 8. End-of-File Signaling

EOF is signaled by a **DATA packet with an empty payload** (payload_len = 0):

1. After the last data chunk is acknowledged, the sender MUST transmit a DATA packet with `payload_len = 0` and the next sequential `seq_num`.
2. The receiver MUST interpret a DATA packet with an empty payload as the EOF marker.
3. The receiver MUST send an ACK for the EOF packet.
4. Upon receiving the ACK, the sender proceeds to session termination.

This approach avoids the need for a separate message type and allows the receiver to distinguish between "more data coming" and "transfer complete" unambiguously.

---

## 9. Protocol Termination

Session termination follows a **FIN / FIN-ACK** exchange:

1. After the file transfer is complete, the client MUST send a `FIN` packet.
2. The server MUST respond with a `FIN-ACK` packet.
3. If the `FIN-ACK` is not received within `TIMEOUT`, the client MUST retransmit the `FIN` up to `MAX_RETRIES` times.
4. Upon successful exchange, both sides MUST release all session resources (buffers, state).
5. If `MAX_RETRIES` is exceeded, the initiator SHOULD force-close the session and log a warning.

---

## 10. Configuration Parameters

| Parameter | Default | Description |
|---|---|---|
| `SERVER_HOST` | `127.0.0.1` | Server listen address |
| `SERVER_PORT` | `12345` | Server listen port |
| `CHUNK_SIZE` | `1024` | Maximum DATA payload size in bytes |
| `TIMEOUT` | `2.0` | Socket timeout in seconds |
| `MAX_RETRIES` | `5` | Maximum retransmission attempts |
| `SERVER_FILES_DIR` | `server_files` | Directory for server-side file storage |
| `SIMULATE_LOSS` | `False` | Enable simulated packet loss for testing |
| `LOSS_PROBABILITY` | `0.3` | Probability of dropping a packet when simulation is enabled |

---

## 11. Testing

### 11.1 Simulated Packet Loss

For testing reliability mechanisms without external tools, the implementation includes a **configurable packet loss simulator**:

- Set `SIMULATE_LOSS = True` in `config.py`
- Adjust `LOSS_PROBABILITY` (0.0 to 1.0) to control loss rate
- Both client and server independently simulate loss on received packets
- Console logs indicate when packets are dropped (`[SIM]` prefix)

This allows verification that:
- Retransmission is triggered correctly upon timeout
- Files transfer completely and correctly despite packet loss
- The protocol recovers gracefully from multiple consecutive losses
