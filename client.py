"""
client.py - RUDP File Transfer Client.

A UDP-based client that implements reliable data transfer using a custom
application-layer protocol. Supports downloading files from the server
and uploading files to the server, with session management, sequenced
data packets, acknowledgements, retransmission, and clean termination.

Usage:
    python client.py

The client connects to the server configured in config.py and presents
an interactive command-line menu.
"""

import os
import sys
import socket
import time

from config import (
    SERVER_HOST, SERVER_PORT, CHUNK_SIZE, TIMEOUT, MAX_RETRIES,
    SIMULATE_LOSS, LOSS_PROBABILITY,
)
from protocol import (
    HEADER_SIZE,
    MSG_SYN, MSG_SYN_ACK, MSG_ACK, MSG_DATA, MSG_FIN, MSG_FIN_ACK, MSG_ERROR,
    pack_packet, unpack_packet, msg_name,
    ChecksumError, MalformedPacketError,
)

import random


# --- Logging Helpers --------------------------------------------------
def log(msg: str) -> None:
    """Print a timestamped log message."""
    ts = time.strftime("%H:%M:%S")
    print(f"[CLIENT {ts}] {msg}")


def should_drop() -> bool:
    """Return True if this packet should be simulated as lost."""
    if SIMULATE_LOSS:
        if random.random() < LOSS_PROBABILITY:
            return True
    return False


# --- Session Handshake ------------------------------------------------
def perform_handshake(sock: socket.socket, server_addr: tuple,
                      command: str) -> int:
    """
    Perform a three-way handshake with the server:
      Client -> SYN (with command)
      Server -> SYN-ACK (with session params)
      Client -> ACK

    Parameters
    ----------
    sock        : UDP socket
    server_addr : (host, port) of the server
    command     : e.g. "DOWNLOAD:test.txt" or "UPLOAD:test.txt"

    Returns
    -------
    int : The session_id assigned by the server.

    Raises
    ------
    TimeoutError : if handshake fails after MAX_RETRIES.
    ConnectionError : if server responds with an ERROR.
    """
    syn_payload = command.encode("utf-8")
    syn_pkt = pack_packet(MSG_SYN, 0, 0, syn_payload)

    session_id = None

    for attempt in range(1, MAX_RETRIES + 1):
        sock.sendto(syn_pkt, server_addr)
        log(f"-> Sent SYN: \"{command}\" (attempt {attempt}/{MAX_RETRIES})")

        try:
            data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
        except socket.timeout:
            log(f"[..] Timeout waiting for SYN-ACK (attempt {attempt})")
            continue

        if should_drop():
            log(f"[X] [SIM] Dropped incoming SYN-ACK (simulated loss)")
            continue

        try:
            r_type, r_sid, r_seq, r_payload = unpack_packet(data)
        except (ChecksumError, MalformedPacketError) as e:
            log(f"[!] Bad packet: {e}")
            continue

        if r_type == MSG_ERROR:
            error_msg = r_payload.decode("utf-8", errors="replace")
            raise ConnectionError(f"Server error: {error_msg}")

        if r_type == MSG_SYN_ACK:
            session_id = r_sid
            params = r_payload.decode("utf-8", errors="replace")
            log(f"<- Received SYN-ACK (session={session_id}, params={params})")

            # Send ACK to complete handshake
            ack_pkt = pack_packet(MSG_ACK, session_id, 0)
            sock.sendto(ack_pkt, server_addr)
            log(f"-> Sent ACK – handshake complete!")
            return session_id
        else:
            log(f"[!] Unexpected {msg_name(r_type)} during handshake")

    raise TimeoutError("Handshake failed: no SYN-ACK received")


# --- Download File ----------------------------------------------------
def download_file(sock: socket.socket, server_addr: tuple,
                  session_id: int, filename: str) -> None:
    """
    Receive a file from the server. Expects sequenced DATA packets,
    sends ACK for each. Empty DATA payload signals EOF. Reassembles
    data in sequence-number order and saves to local disk.
    """
    log(f"[DL] Downloading: {filename}")

    received_data = {}   # seq_num -> payload
    expected_seq = 0

    while True:
        try:
            data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
        except socket.timeout:
            log(f"[..] Timeout waiting for DATA (expected seq={expected_seq})")
            continue

        if should_drop():
            log(f"[X] [SIM] Dropped incoming DATA (simulated loss)")
            continue

        try:
            r_type, r_sid, r_seq, r_payload = unpack_packet(data)
        except (ChecksumError, MalformedPacketError) as e:
            log(f"[!] Bad packet: {e}")
            continue

        # Session mismatch check
        if r_sid != session_id:
            log(f"[!] Session mismatch: got {r_sid}, expected {session_id}")
            continue

        if r_type == MSG_ERROR:
            error_msg = r_payload.decode("utf-8", errors="replace")
            log(f"[ERR] Server error: {error_msg}")
            return

        if r_type == MSG_DATA:
            # Empty payload = EOF
            if len(r_payload) == 0:
                log(f"[EOF] Received EOF signal (seq={r_seq})")
                # Send ACK for EOF
                ack_pkt = pack_packet(MSG_ACK, session_id, r_seq)
                sock.sendto(ack_pkt, server_addr)
                log(f"-> Sent ACK for EOF seq={r_seq}")
                break

            log(f"<- Received DATA seq={r_seq} ({len(r_payload)} bytes)")

            # Store data
            received_data[r_seq] = r_payload

            # Send ACK
            ack_pkt = pack_packet(MSG_ACK, session_id, r_seq)
            sock.sendto(ack_pkt, server_addr)
            log(f"-> Sent ACK for seq={r_seq}")

            if r_seq == expected_seq:
                expected_seq += 1
        else:
            log(f"[!] Unexpected {msg_name(r_type)} during download")

    # Reassemble file in order
    file_bytes = b""
    for seq in sorted(received_data.keys()):
        file_bytes += received_data[seq]

    # Save file locally
    with open(filename, "wb") as f:
        f.write(file_bytes)

    log(f"[OK] File saved: {filename} ({len(file_bytes)} bytes)")


# --- Upload File ------------------------------------------------------
def upload_file(sock: socket.socket, server_addr: tuple,
                session_id: int, filename: str) -> None:
    """
    Send a local file to the server using sequenced DATA packets with
    stop-and-wait ARQ. Sends an empty DATA packet as EOF signal.
    """
    if not os.path.isfile(filename):
        log(f"[ERR] Local file not found: {filename}")
        return

    file_size = os.path.getsize(filename)
    log(f"[UL] Uploading: {filename} ({file_size} bytes)")

    with open(filename, "rb") as f:
        file_data = f.read()

    seq_num = 0
    offset = 0

    while offset < len(file_data):
        chunk = file_data[offset:offset + CHUNK_SIZE]
        pkt = pack_packet(MSG_DATA, session_id, seq_num, chunk)

        ack_received = False
        for attempt in range(1, MAX_RETRIES + 1):
            sock.sendto(pkt, server_addr)
            log(f"-> Sent DATA seq={seq_num} ({len(chunk)} bytes) "
                f"(attempt {attempt}/{MAX_RETRIES})")

            try:
                data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
            except socket.timeout:
                log(f"[..] Timeout waiting for ACK seq={seq_num} "
                    f"(attempt {attempt})")
                continue

            if should_drop():
                log(f"[X] [SIM] Dropped incoming ACK (simulated loss)")
                continue

            try:
                r_type, r_sid, r_seq, r_payload = unpack_packet(data)
            except (ChecksumError, MalformedPacketError) as e:
                log(f"[!] Bad packet: {e}")
                continue

            if r_sid != session_id:
                log(f"[!] Session mismatch in ACK")
                continue

            if r_type == MSG_ACK and r_seq == seq_num:
                log(f"<- Received ACK for seq={seq_num}")
                ack_received = True
                break
            else:
                log(f"[!] Unexpected {msg_name(r_type)} seq={r_seq}")

        if not ack_received:
            log(f"[ERR] Upload failed: no ACK for seq={seq_num}")
            return

        seq_num += 1
        offset += CHUNK_SIZE

    # Send empty DATA to signal EOF
    eof_pkt = pack_packet(MSG_DATA, session_id, seq_num, b"")
    for attempt in range(1, MAX_RETRIES + 1):
        sock.sendto(eof_pkt, server_addr)
        log(f"-> Sent EOF signal (empty DATA seq={seq_num}) "
            f"(attempt {attempt}/{MAX_RETRIES})")

        try:
            data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
        except socket.timeout:
            log(f"[..] Timeout waiting for ACK on EOF (attempt {attempt})")
            continue

        if should_drop():
            log(f"[X] [SIM] Dropped incoming ACK for EOF (simulated loss)")
            continue

        try:
            r_type, r_sid, r_seq, r_payload = unpack_packet(data)
        except (ChecksumError, MalformedPacketError):
            continue

        if r_type == MSG_ACK and r_seq == seq_num:
            log(f"<- Received ACK for EOF seq={seq_num}")
            break

    log(f"[OK] Upload complete: {filename}")


# --- Session Termination ---------------------------------------------
def perform_termination(sock: socket.socket, server_addr: tuple,
                        session_id: int) -> None:
    """
    Initiate clean session termination:
      Client -> FIN
      Server -> FIN-ACK
    """
    fin_pkt = pack_packet(MSG_FIN, session_id, 0)

    for attempt in range(1, MAX_RETRIES + 1):
        sock.sendto(fin_pkt, server_addr)
        log(f"-> Sent FIN (attempt {attempt}/{MAX_RETRIES})")

        try:
            data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
        except socket.timeout:
            log(f"[..] Timeout waiting for FIN-ACK (attempt {attempt})")
            continue

        if should_drop():
            log(f"[X] [SIM] Dropped incoming FIN-ACK (simulated loss)")
            continue

        try:
            r_type, r_sid, r_seq, r_payload = unpack_packet(data)
        except (ChecksumError, MalformedPacketError) as e:
            log(f"[!] Bad packet: {e}")
            continue

        if r_type == MSG_FIN_ACK and r_sid == session_id:
            log(f"<- Received FIN-ACK – session terminated cleanly")
            return
        else:
            log(f"[!] Unexpected {msg_name(r_type)} during termination")

    log(f"[!] FIN-ACK not received, forcing session close")


# --- Main Client Loop ------------------------------------------------
def main():
    """Interactive client for the RUDP file transfer protocol."""

    server_addr = (SERVER_HOST, SERVER_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    log(f"RUDP Client ready. Server: {SERVER_HOST}:{SERVER_PORT}")
    if SIMULATE_LOSS:
        log(f"[!] Simulated loss ENABLED (probability={LOSS_PROBABILITY})")

    print("\nCommands:")
    print("  download <filename>  - Download a file from the server")
    print("  upload <filename>    - Upload a local file to the server")
    print("  exit                 - Quit the client\n")

    while True:
        try:
            user_input = input("rudp> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            log("Client shutting down...")
            break

        if not user_input:
            continue

        parts = user_input.split(maxsplit=1)
        cmd = parts[0].lower()

        if cmd == "exit":
            log("Goodbye!")
            break
        elif cmd in ("download", "upload"):
            if len(parts) < 2:
                print(f"Usage: {cmd} <filename>")
                continue

            filename = parts[1]

            if cmd == "download":
                command_str = f"DOWNLOAD:{filename}"
            else:
                # For upload, verify local file exists first
                if not os.path.isfile(filename):
                    log(f"[ERR] Local file not found: {filename}")
                    continue
                command_str = f"UPLOAD:{os.path.basename(filename)}"

            # -- Handshake -----------------------------------------
            try:
                session_id = perform_handshake(sock, server_addr, command_str)
            except TimeoutError as e:
                log(f"[ERR] {e}")
                continue
            except ConnectionError as e:
                log(f"[ERR] {e}")
                continue

            print()

            # -- File Transfer -------------------------------------
            try:
                if cmd == "download":
                    download_file(sock, server_addr, session_id, filename)
                else:
                    upload_file(sock, server_addr, session_id, filename)
            except Exception as e:
                log(f"[ERR] Transfer error: {e}")

            print()

            # -- Termination ---------------------------------------
            perform_termination(sock, server_addr, session_id)
            print()
        else:
            print(f"Unknown command: {cmd}")
            print("Commands: download <filename>, upload <filename>, exit")

    sock.close()


if __name__ == "__main__":
    main()
