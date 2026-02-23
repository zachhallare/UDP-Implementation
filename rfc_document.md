# RUDP – Reliable Data Transfer over UDP

## RFC-Style Protocol Specification

**Document Title:** RUDP File Transfer Protocol Specification  
**Version:** 1.0  
**Date:** February 2025  
**Authors:** Zach Hallare & Nathan Laborada

---

## 1. Introduction

This document specifies the **Reliable UDP (RUDP) File Transfer Protocol**, a custom application-layer protocol built on top of UDP. RUDP provides reliable, ordered data delivery and session management for file transfer operations (upload and download).

### 1.1 Motivation

UDP provides connectionless, best-effort delivery with minimal overhead but does not guarantee reliable delivery, ordered delivery, or session management. Many Internet protocols (DHCP, DNS, TFTP, NTP) intentionally use UDP and implement their own control mechanisms at the application layer.

RUDP demonstrates how these features can be achieved using:
- Three-way handshake for session establishment
- Sequenced data packets with Stop-and-Wait ARQ
- Timeout-based retransmission
- FIN/FIN-ACK session termination
- CRC-16 checksum for integrity
- XOR encryption for payload confidentiality
- HMAC-SHA256 for packet authentication

### 1.2 Terminology

The key words "MUST", "SHOULD", "MAY", and "MUST NOT" are to be interpreted as described in RFC 2119.

- **Client**: The endpoint that initiates sessions and requests file operations.
- **Server**: The endpoint that listens for sessions and serves or receives files.
- **Session**: A logical connection identified by a unique `session_id`.
- **Packet**: A single RUDP message consisting of a header, optional payload, and HMAC.

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

Every RUDP packet on the wire has the structure:

```
[13-byte Header] [Encrypted Payload (variable)] [32-byte HMAC-SHA256]
```

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
|                   encrypted payload (variable)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       HMAC-SHA256 (32 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Field Descriptions

| Field | Size | Encoding | Description |
|---|---|---|---|
| `msg_type` | 1 byte | Unsigned integer (big-endian) | Identifies the packet type (see §3.3) |
| `session_id` | 4 bytes | Unsigned 32-bit integer (big-endian) | Unique session identifier assigned by the server |
| `seq_num` | 4 bytes | Unsigned 32-bit integer (big-endian) | Sequence number for ordering and acknowledgement |
| `payload_len` | 2 bytes | Unsigned 16-bit integer (big-endian) | Length of the encrypted payload in bytes |
| `checksum` | 2 bytes | Unsigned 16-bit integer (big-endian) | CRC-16/CCITT-FALSE over header + encrypted payload (checksum field zeroed during computation) |
| `payload` | variable | XOR-encrypted raw bytes | Encrypted file data or command string |
| `HMAC` | 32 bytes | HMAC-SHA256 digest | Authentication tag over header + encrypted payload |

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

- **SYN** payload: UTF-8 command string, e.g., `"DOWNLOAD:filename.txt"` or `"UPLOAD:filename.txt"`
- **SYN-ACK** payload: UTF-8 session parameters, e.g., `"SESSION:12345|CHUNK:1024|OP:DOWNLOAD"`
- **ACK** payload: Empty (0 bytes)
- **DATA** payload: Raw binary file data (up to `CHUNK_SIZE` bytes). Empty payload (0 bytes) = EOF.
- **FIN / FIN-ACK** payload: Empty (0 bytes)
- **ERROR** payload: UTF-8 error message string

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

1. The sender MUST transmit one DATA packet and wait for an ACK before sending the next.
2. Each DATA packet MUST carry a monotonically increasing sequence number starting from 0.
3. The receiver MUST respond with an ACK containing the sequence number of the received DATA packet.
4. Duplicate DATA packets SHOULD be accepted but not double-processed; the receiver MUST re-send the ACK.

### 5.2 Timeout and Retransmission

- The sender MUST set a socket timeout of `TIMEOUT` seconds (default: 2.0s).
- If no response is received within the timeout, the sender MUST retransmit the packet.
- If `MAX_RETRIES` consecutive timeouts occur (default: 5), the sender MUST abort and report an error.

### 5.3 Sequencing and Ordering

- The receiver MUST store received data indexed by sequence number.
- Upon EOF, the receiver MUST reassemble the file by concatenating payloads in ascending sequence-number order.

### 5.4 Checksum Verification (CRC-16)

- Every packet MUST include a CRC-16/CCITT-FALSE checksum in the header.
- The checksum is computed over the header + encrypted payload with the checksum field zeroed.
- Packets with invalid checksums MUST be silently discarded.

### 5.5 Encryption (XOR Cipher)

- All DATA payloads MUST be encrypted using repeating-key XOR with the shared secret key before transmission.
- The receiver MUST decrypt the payload after checksum and HMAC verification.
- This ensures payload confidentiality — packet contents appear scrambled to any observer (e.g., Wireshark).

### 5.6 Authentication (HMAC-SHA256)

- Every packet MUST have a 32-byte HMAC-SHA256 digest appended after the header + encrypted payload.
- The HMAC is computed over the entire packet body (header + encrypted payload) using the shared secret key.
- The receiver MUST verify the HMAC before processing. Packets that fail verification MUST be discarded.
- This prevents packet forgery and tampering.

---

## 6. Error Handling

### 6.1 Timeout – Unresponsive Peer

- If a peer does not respond within `TIMEOUT` seconds, the packet MUST be retransmitted.
- After `MAX_RETRIES` consecutive failures, the session MUST be terminated with an error logged.

### 6.2 File Not Found

- If the server receives a `DOWNLOAD` request for a nonexistent file, it MUST respond with an `ERROR` packet containing `"File not found: <filename>"`.
- The client MUST display the error and proceed to session termination.

### 6.3 Session Mismatch

- Packets with a `session_id` that does not match the current session MUST be silently discarded.

### 6.4 Malformed Packets

- Packets shorter than `HEADER_SIZE + HMAC_SIZE` (45 bytes) MUST be discarded.
- Packets where `payload_len` does not match the actual payload size MUST be discarded.

### 6.5 Authentication Failure

- Packets that fail HMAC-SHA256 verification MUST be discarded and logged.

---

## 7. File Transfer Operations

### 7.1 Download (Server → Client)

1. Client sends `SYN` with payload `"DOWNLOAD:<filename>"`.
2. Server validates the file exists and responds with `SYN-ACK`.
3. Server sends the file as sequenced, encrypted `DATA` packets (up to `CHUNK_SIZE` bytes each).
4. Client sends `ACK` for each DATA packet.
5. Transfer is binary-safe.

### 7.2 Upload (Client → Server)

1. Client sends `SYN` with payload `"UPLOAD:<filename>"`.
2. Server responds with `SYN-ACK`.
3. Client sends the file as sequenced, encrypted `DATA` packets.
4. Server sends `ACK` for each and reassembles upon EOF.
5. Transfer is binary-safe.

---

## 8. End-of-File Signaling

EOF is signaled by a **DATA packet with an empty payload** (payload_len = 0):

1. After the last chunk is acknowledged, the sender MUST transmit a DATA packet with `payload_len = 0`.
2. The receiver MUST interpret this as the EOF marker and send an ACK.
3. Upon receiving the ACK, the sender proceeds to session termination.

---

## 9. Protocol Termination

1. After the file transfer is complete, the client MUST send a `FIN` packet.
2. The server MUST respond with a `FIN-ACK` packet.
3. If `FIN-ACK` is not received within `TIMEOUT`, the client MUST retransmit `FIN` up to `MAX_RETRIES` times.
4. Upon successful exchange, both sides MUST release all session resources.
5. If `MAX_RETRIES` is exceeded, the initiator SHOULD force-close and log a warning.

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
| `SHARED_SECRET` | `rudp-secret-key-2025` | Shared key for XOR encryption and HMAC |
| `SIMULATE_LOSS` | `False` | Enable simulated packet loss for testing |
| `LOSS_PROBABILITY` | `0.3` | Probability of dropping a packet when simulation is enabled |

---

## 11. Testing

### 11.1 Simulated Packet Loss

For testing reliability without external tools:

- Set `SIMULATE_LOSS = True` in `protocol.py`
- Adjust `LOSS_PROBABILITY` to control loss rate
- Console logs show dropped packets with `[SIM]` prefix
- Verifies retransmission, complete file transfer despite loss, and graceful recovery
