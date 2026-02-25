"""
server.py - RUDP File Transfer Server.

A UDP-based server that implements reliable data transfer using a custom
application-layer protocol. Supports file download (server -> client) and
file upload (client -> server) with session management, sequenced data
packets, acknowledgements, retransmission handling, and clean termination.

Usage:
    python server.py

@author Zach Benedict Hallare & Nathan Laborada
@since February 2025
"""

import os
import sys
import socket
import random
import time

from protocol import (
    # Config constants
    SERVER_HOST, SERVER_PORT, CHUNK_SIZE, TIMEOUT, MAX_RETRIES,
    SERVER_FILES_DIR, SIMULATE_LOSS, LOSS_PROBABILITY,
    # Protocol constants and functions
    HEADER_SIZE, HMAC_SIZE,
    MSG_SYN, MSG_SYN_ACK, MSG_ACK, MSG_DATA, MSG_FIN, MSG_FIN_ACK, MSG_ERROR,
    pack_packet, unpack_packet, msg_name,
    ChecksumError, MalformedPacketError, AuthenticationError,
)

# Maximum receive buffer size (header + payload + HMAC + margin)
RECV_BUF = HEADER_SIZE + CHUNK_SIZE + HMAC_SIZE + 256


# ===================================================================
# Logging Helpers
# ===================================================================

def log(msg):
    """
    Print a timestamped log message prefixed with [SERVER].

    @param msg: string message to log
    """
    ts = time.strftime("%H:%M:%S")
    print(f"[SERVER {ts}] {msg}")


def should_drop():
    """
    Determine if a packet should be simulated as lost.
    Used for testing retransmission behavior.

    @return: True if the packet should be dropped, False otherwise
    """
    if SIMULATE_LOSS and random.random() < LOSS_PROBABILITY:
        return True
    return False


# ===================================================================
# Reliable Send Helper
# ===================================================================

def reliable_send(sock, addr, msg_type, session_id, seq_num,
                  payload=b"", expect_type=None, expect_session=None):
    """
    Send a packet and wait for a specific response, retransmitting
    on timeout up to MAX_RETRIES times.

    @param sock: UDP socket object
    @param addr: tuple (host, port) of the remote peer
    @param msg_type: integer message type to send (one of MSG_* constants)
    @param session_id: 32-bit unsigned session identifier
    @param seq_num: 32-bit unsigned sequence number
    @param payload: bytes optional payload data
    @param expect_type: integer expected response message type, or None to not wait
    @param expect_session: integer expected session_id in the response, or None to skip check
    @return: tuple (msg_type, session_id, seq_num, payload) of the response,
             or None if expect_type is None
    @raises TimeoutError: if MAX_RETRIES exceeded without receiving expected response
    """
    pkt = pack_packet(msg_type, session_id, seq_num, payload)

    for attempt in range(1, MAX_RETRIES + 1):
        sock.sendto(pkt, addr)
        log(f"  -> Sent {msg_name(msg_type)} seq={seq_num} to {addr}"
            f" (attempt {attempt}/{MAX_RETRIES})")

        if expect_type is None:
            return None

        try:
            data, recv_addr = sock.recvfrom(RECV_BUF)
        except socket.timeout:
            log(f"  [..] Timeout waiting for {msg_name(expect_type)} "
                f"(attempt {attempt})")
            continue

        # Simulated packet loss on receive side
        if should_drop():
            log(f"  [X] [SIM] Dropped incoming packet (simulated loss)")
            continue

        try:
            r_type, r_sid, r_seq, r_payload = unpack_packet(data)
        except (ChecksumError, MalformedPacketError, AuthenticationError) as e:
            log(f"  [!] Bad packet: {e}")
            continue

        # Validate expected message type and session
        if r_type == expect_type:
            if expect_session is not None and r_sid != expect_session:
                log(f"  [!] Session mismatch: got {r_sid}, "
                    f"expected {expect_session}")
                continue
            return r_type, r_sid, r_seq, r_payload

        log(f"  [!] Unexpected {msg_name(r_type)}, expected "
            f"{msg_name(expect_type)}")

    raise TimeoutError(
        f"No response after {MAX_RETRIES} attempts "
        f"(expected {msg_name(expect_type)})")


# ===================================================================
# Handle Download (Server sends file to Client)
# ===================================================================

def handle_download(sock, addr, session_id, filename):
    """
    Read a file from SERVER_FILES_DIR and send it reliably to the
    client using sequenced DATA packets with stop-and-wait ARQ.
    Sends an ERROR packet if the file does not exist.

    @param sock: bound UDP socket object
    @param addr: tuple (host, port) of the client
    @param session_id: 32-bit unsigned session identifier
    @param filename: string name of the file to send
    """
    filepath = os.path.join(SERVER_FILES_DIR, filename)

    # Check if file exists; send ERROR if not found
    if not os.path.isfile(filepath):
        log(f"  [ERR] File not found: {filename}")
        error_msg = f"File not found: {filename}"
        pkt = pack_packet(MSG_ERROR, session_id, 0, error_msg.encode())
        sock.sendto(pkt, addr)
        return

    file_size = os.path.getsize(filepath)
    log(f"  [FILE] Sending file: {filename} ({file_size} bytes)")

    # Read entire file into memory
    with open(filepath, "rb") as f:
        file_data = f.read()

    # Send DATA packets using stop-and-wait ARQ
    seq_num = 0
    offset = 0

    while offset < len(file_data):
        chunk = file_data[offset:offset + CHUNK_SIZE]
        try:
            resp = reliable_send(
                sock, addr, MSG_DATA, session_id, seq_num,
                payload=chunk, expect_type=MSG_ACK,
                expect_session=session_id)
        except TimeoutError:
            log(f"  [ERR] Transfer failed: timeout sending DATA seq={seq_num}")
            return

        r_type, r_sid, r_seq, r_payload = resp
        log(f"  <- Received ACK for seq={r_seq}")
        seq_num += 1
        offset += CHUNK_SIZE

    # Send empty DATA packet to signal EOF
    try:
        reliable_send(
            sock, addr, MSG_DATA, session_id, seq_num,
            payload=b"", expect_type=MSG_ACK,
            expect_session=session_id)
        log(f"  [OK] EOF signal sent (empty DATA seq={seq_num})")
    except TimeoutError:
        log(f"  [WARN] Timeout sending EOF signal")

    log(f"  [OK] File download complete: {filename}")


# ===================================================================
# Handle Upload (Client sends file to Server)
# ===================================================================

def handle_upload(sock, addr, session_id, filename):
    """
    Receive a file from the client and store it in SERVER_FILES_DIR.
    Expects sequenced DATA packets and sends ACK for each one.
    Reassembles the file in sequence order upon receiving the EOF signal.

    @param sock: bound UDP socket object
    @param addr: tuple (host, port) of the client
    @param session_id: 32-bit unsigned session identifier
    @param filename: string name of the file to store
    """
    filepath = os.path.join(SERVER_FILES_DIR, filename)
    log(f"  [FILE] Receiving file: {filename}")

    received_data = {}   # seq_num -> payload bytes
    expected_seq = 0

    while True:
        try:
            data, recv_addr = sock.recvfrom(RECV_BUF)
        except socket.timeout:
            log(f"  [..] Timeout waiting for DATA (expected seq={expected_seq})")
            continue

        # Simulated packet loss on receive side
        if should_drop():
            log(f"  [X] [SIM] Dropped incoming DATA (simulated loss)")
            continue

        try:
            r_type, r_sid, r_seq, r_payload = unpack_packet(data)
        except (ChecksumError, MalformedPacketError, AuthenticationError) as e:
            log(f"  [!] Bad packet: {e}")
            continue

        # Session mismatch check
        if r_sid != session_id:
            log(f"  [!] Session mismatch: got {r_sid}, expected {session_id}")
            continue

        if r_type == MSG_DATA:
            # Empty payload = EOF signal
            if len(r_payload) == 0:
                log(f"  [EOF] Received EOF signal (seq={r_seq})")
                ack_pkt = pack_packet(MSG_ACK, session_id, r_seq)
                sock.sendto(ack_pkt, recv_addr)
                log(f"  -> Sent ACK for EOF seq={r_seq}")
                break

            log(f"  <- Received DATA seq={r_seq} "
                f"({len(r_payload)} bytes)")

            # Store the data (supports out-of-order and duplicate handling)
            received_data[r_seq] = r_payload

            # Send ACK for the received packet
            ack_pkt = pack_packet(MSG_ACK, session_id, r_seq)
            sock.sendto(ack_pkt, recv_addr)
            log(f"  -> Sent ACK for seq={r_seq}")

            if r_seq == expected_seq:
                expected_seq += 1
        elif r_type == MSG_FIN:
            # Client wants to terminate early
            log(f"  [!] Received FIN during upload, aborting")
            fin_ack = pack_packet(MSG_FIN_ACK, session_id, r_seq)
            sock.sendto(fin_ack, recv_addr)
            return
        else:
            log(f"  [!] Unexpected {msg_name(r_type)} during upload")

    # Reassemble file in ascending sequence order
    file_bytes = b""
    for seq in sorted(received_data.keys()):
        file_bytes += received_data[seq]

    # Write the reassembled file to disk
    with open(filepath, "wb") as f:
        f.write(file_bytes)

    log(f"  [OK] File uploaded: {filename} ({len(file_bytes)} bytes)")


# ===================================================================
# Handle Session Termination
# ===================================================================

def handle_termination(sock, addr, session_id):
    """
    Perform FIN/FIN-ACK termination. The server waits for a FIN from the
    client, responds with FIN-ACK, and considers the session closed.

    @param sock: bound UDP socket object
    @param addr: tuple (host, port) of the client
    @param session_id: 32-bit unsigned session identifier
    """
    log(f"  [FIN] Waiting for FIN from client...")
    retries = 0

    while retries < MAX_RETRIES:
        try:
            data, recv_addr = sock.recvfrom(RECV_BUF)
        except socket.timeout:
            retries += 1
            log(f"  [..] Timeout waiting for FIN (attempt {retries})")
            continue

        if should_drop():
            log(f"  [X] [SIM] Dropped incoming FIN (simulated loss)")
            continue

        try:
            r_type, r_sid, r_seq, r_payload = unpack_packet(data)
        except (ChecksumError, MalformedPacketError, AuthenticationError) as e:
            log(f"  [!] Bad packet: {e}")
            continue

        if r_type == MSG_FIN and r_sid == session_id:
            log(f"  <- Received FIN seq={r_seq}")
            # Send FIN-ACK to confirm termination
            fin_ack = pack_packet(MSG_FIN_ACK, session_id, r_seq)
            sock.sendto(fin_ack, recv_addr)
            log(f"  -> Sent FIN-ACK seq={r_seq}")
            log(f"  [OK] Session {session_id} terminated cleanly")
            return
        else:
            log(f"  [!] Unexpected {msg_name(r_type)} while waiting for FIN")

    log(f"  [!] Session {session_id} termination timed out")


# ===================================================================
# Main Server Loop
# ===================================================================

def main():
    """
    Start the RUDP server and listen for incoming client sessions.
    Creates the server files directory, binds a UDP socket, and enters
    an infinite loop waiting for SYN packets from clients.
    """
    # Create server files directory if it doesn't exist
    os.makedirs(SERVER_FILES_DIR, exist_ok=True)

    # Create and bind UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_HOST, SERVER_PORT))
    sock.settimeout(None)  # Blocking mode for the main listen loop

    log(f"Server started on {SERVER_HOST}:{SERVER_PORT}")
    log(f"Serving files from: {os.path.abspath(SERVER_FILES_DIR)}")
    if SIMULATE_LOSS:
        log(f"[!] Simulated loss ENABLED (probability={LOSS_PROBABILITY})")
    log("Encryption: XOR  |  Authentication: HMAC-SHA256")
    log("Waiting for connections...\n")

    while True:
        try:
            # Wait for incoming SYN packet (blocking)
            data, addr = sock.recvfrom(RECV_BUF)

            if should_drop():
                log(f"[X] [SIM] Dropped incoming SYN (simulated loss)")
                continue

            try:
                r_type, r_sid, r_seq, r_payload = unpack_packet(data)
            except (ChecksumError, MalformedPacketError, AuthenticationError) as e:
                log(f"[!] Bad packet from {addr}: {e}")
                continue

            if r_type != MSG_SYN:
                log(f"[!] Expected SYN, got {msg_name(r_type)} from {addr}")
                continue

            # Parse SYN payload to determine the requested command
            command_str = r_payload.decode("utf-8", errors="replace")
            log(f"<- Received SYN from {addr}: \"{command_str}\"")

            if command_str.startswith("DOWNLOAD:"):
                filename = command_str[len("DOWNLOAD:"):]
                operation = "DOWNLOAD"
            elif command_str.startswith("UPLOAD:"):
                filename = command_str[len("UPLOAD:"):]
                operation = "UPLOAD"
            else:
                log(f"[!] Unknown command: {command_str}")
                error_pkt = pack_packet(
                    MSG_ERROR, 0, 0,
                    f"Unknown command: {command_str}".encode())
                sock.sendto(error_pkt, addr)
                continue

            # Generate a random session ID for this session
            session_id = random.randint(1, 0xFFFFFFFF)
            log(f"  [SES] New session: id={session_id}, "
                f"op={operation}, file={filename}")

            # Send SYN-ACK with negotiated session parameters
            syn_ack_payload = (
                f"SESSION:{session_id}|CHUNK:{CHUNK_SIZE}|OP:{operation}"
            ).encode()
            syn_ack_pkt = pack_packet(
                MSG_SYN_ACK, session_id, 0, syn_ack_payload)
            sock.sendto(syn_ack_pkt, addr)
            log(f"  -> Sent SYN-ACK (session={session_id})")

            # Wait for ACK to complete the three-way handshake
            sock.settimeout(TIMEOUT)
            ack_received = False
            for attempt in range(MAX_RETRIES):
                try:
                    data, recv_addr = sock.recvfrom(RECV_BUF)
                except socket.timeout:
                    log(f"  [..] Timeout waiting for ACK "
                        f"(attempt {attempt + 1})")
                    # Resend SYN-ACK on timeout
                    sock.sendto(syn_ack_pkt, addr)
                    log(f"  -> Resent SYN-ACK")
                    continue

                if should_drop():
                    log(f"  [X] [SIM] Dropped incoming ACK (simulated loss)")
                    continue

                try:
                    r_type, r_sid, r_seq, r_payload = unpack_packet(data)
                except (ChecksumError, MalformedPacketError,
                        AuthenticationError) as e:
                    log(f"  [!] Bad packet: {e}")
                    continue

                if r_type == MSG_ACK and r_sid == session_id:
                    ack_received = True
                    log(f"  <- Received ACK – handshake complete!")
                    break
                else:
                    log(f"  [!] Unexpected {msg_name(r_type)} "
                        f"during handshake")

            if not ack_received:
                log(f"  [ERR] Handshake failed (no ACK received)")
                sock.settimeout(None)
                continue

            # Execute the requested file operation
            log(f"  === Starting {operation} of \"{filename}\" ===")

            if operation == "DOWNLOAD":
                handle_download(sock, addr, session_id, filename)
            elif operation == "UPLOAD":
                handle_upload(sock, addr, session_id, filename)

            # Perform session termination (FIN/FIN-ACK)
            handle_termination(sock, addr, session_id)

            # Reset to blocking mode for next session
            sock.settimeout(None)
            log(f"  === Session {session_id} ended ===\n")
            log("Waiting for connections...\n")

        except KeyboardInterrupt:
            log("Server shutting down...")
            sock.close()
            sys.exit(0)
        except Exception as e:
            log(f"[X] Unexpected error: {e}")
            sock.settimeout(None)
            continue


if __name__ == "__main__":
    main()
