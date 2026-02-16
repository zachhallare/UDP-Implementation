"""
test_rudp.py - Automated test script for the RUDP protocol.

Runs the server in a background thread and tests download, upload,
file-not-found, and session termination scenarios automatically.
"""

import os
import sys
import time
import threading
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from config import SERVER_HOST, SERVER_PORT, SERVER_FILES_DIR, CHUNK_SIZE, TIMEOUT, MAX_RETRIES
from protocol import (
    HEADER_SIZE, MSG_SYN, MSG_SYN_ACK, MSG_ACK, MSG_DATA,
    MSG_FIN, MSG_FIN_ACK, MSG_ERROR,
    pack_packet, unpack_packet, msg_name,
    ChecksumError, MalformedPacketError,
)
import socket
import random


def md5(filepath):
    """Compute MD5 hash of a file."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run_server():
    """Run the server in the current thread (blocking)."""
    import server
    server.main()


def test_download():
    """Test downloading a file from the server."""
    print("\n" + "=" * 60)
    print("TEST: File Download")
    print("=" * 60)

    server_addr = (SERVER_HOST, SERVER_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    # Handshake
    command = "DOWNLOAD:test.txt"
    syn_pkt = pack_packet(MSG_SYN, 0, 0, command.encode())
    sock.sendto(syn_pkt, server_addr)
    print("[TEST] Sent SYN")

    data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
    r_type, r_sid, r_seq, r_payload = unpack_packet(data)
    assert r_type == MSG_SYN_ACK, f"Expected SYN-ACK, got {msg_name(r_type)}"
    session_id = r_sid
    print(f"[TEST] Received SYN-ACK, session={session_id}")

    ack_pkt = pack_packet(MSG_ACK, session_id, 0)
    sock.sendto(ack_pkt, server_addr)
    print("[TEST] Sent ACK – handshake complete")

    # Receive DATA packets
    received = {}
    while True:
        data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
        r_type, r_sid, r_seq, r_payload = unpack_packet(data)

        if r_type == MSG_DATA:
            if len(r_payload) == 0:
                print(f"[TEST] Received EOF (seq={r_seq})")
                ack_pkt = pack_packet(MSG_ACK, session_id, r_seq)
                sock.sendto(ack_pkt, server_addr)
                break
            received[r_seq] = r_payload
            print(f"[TEST] Received DATA seq={r_seq} ({len(r_payload)} bytes)")
            ack_pkt = pack_packet(MSG_ACK, session_id, r_seq)
            sock.sendto(ack_pkt, server_addr)

    # Reassemble
    file_bytes = b""
    for seq in sorted(received.keys()):
        file_bytes += received[seq]

    # Save
    output_path = "downloaded_test.txt"
    with open(output_path, "wb") as f:
        f.write(file_bytes)

    # Termination
    fin_pkt = pack_packet(MSG_FIN, session_id, 0)
    sock.sendto(fin_pkt, server_addr)
    data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
    r_type, r_sid, r_seq, r_payload = unpack_packet(data)
    assert r_type == MSG_FIN_ACK, f"Expected FIN-ACK, got {msg_name(r_type)}"
    print("[TEST] FIN/FIN-ACK exchange complete")

    # Verify
    original = os.path.join(SERVER_FILES_DIR, "test.txt")
    assert md5(original) == md5(output_path), "MD5 mismatch!"
    print(f"[TEST] [OK] PASS – Downloaded file matches original (MD5 verified)")

    sock.close()
    # Clean up
    os.remove(output_path)


def test_upload():
    """Test uploading a file to the server."""
    print("\n" + "=" * 60)
    print("TEST: File Upload")
    print("=" * 60)

    # Create a test file to upload
    upload_filename = "upload_test_file.txt"
    test_content = b"This is a test upload file.\nLine 2\nLine 3 with special chars: !@#$%\n"
    with open(upload_filename, "wb") as f:
        f.write(test_content)

    server_addr = (SERVER_HOST, SERVER_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    # Handshake
    command = f"UPLOAD:{upload_filename}"
    syn_pkt = pack_packet(MSG_SYN, 0, 0, command.encode())
    sock.sendto(syn_pkt, server_addr)
    print("[TEST] Sent SYN")

    data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
    r_type, r_sid, r_seq, r_payload = unpack_packet(data)
    assert r_type == MSG_SYN_ACK, f"Expected SYN-ACK, got {msg_name(r_type)}"
    session_id = r_sid
    print(f"[TEST] Received SYN-ACK, session={session_id}")

    ack_pkt = pack_packet(MSG_ACK, session_id, 0)
    sock.sendto(ack_pkt, server_addr)
    print("[TEST] Sent ACK – handshake complete")

    # Send DATA packets
    with open(upload_filename, "rb") as f:
        file_data = f.read()

    seq_num = 0
    offset = 0
    while offset < len(file_data):
        chunk = file_data[offset:offset + CHUNK_SIZE]
        data_pkt = pack_packet(MSG_DATA, session_id, seq_num, chunk)
        sock.sendto(data_pkt, server_addr)
        print(f"[TEST] Sent DATA seq={seq_num} ({len(chunk)} bytes)")

        resp_data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
        r_type, r_sid, r_seq, r_payload = unpack_packet(resp_data)
        assert r_type == MSG_ACK, f"Expected ACK, got {msg_name(r_type)}"
        print(f"[TEST] Received ACK seq={r_seq}")

        seq_num += 1
        offset += CHUNK_SIZE

    # Send EOF
    eof_pkt = pack_packet(MSG_DATA, session_id, seq_num, b"")
    sock.sendto(eof_pkt, server_addr)
    print(f"[TEST] Sent EOF (empty DATA seq={seq_num})")

    resp_data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
    r_type, r_sid, r_seq, r_payload = unpack_packet(resp_data)
    assert r_type == MSG_ACK, f"Expected ACK for EOF, got {msg_name(r_type)}"
    print("[TEST] Received ACK for EOF")

    # Termination
    fin_pkt = pack_packet(MSG_FIN, session_id, 0)
    sock.sendto(fin_pkt, server_addr)
    data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
    r_type, r_sid, r_seq, r_payload = unpack_packet(data)
    assert r_type == MSG_FIN_ACK, f"Expected FIN-ACK, got {msg_name(r_type)}"
    print("[TEST] FIN/FIN-ACK exchange complete")

    # Verify the uploaded file on server side
    server_file = os.path.join(SERVER_FILES_DIR, upload_filename)
    assert os.path.isfile(server_file), f"Uploaded file not found at {server_file}"
    assert md5(upload_filename) == md5(server_file), "MD5 mismatch!"
    print(f"[TEST] [OK] PASS – Uploaded file matches original (MD5 verified)")

    sock.close()
    # Clean up
    os.remove(upload_filename)
    os.remove(server_file)


def test_file_not_found():
    """Test server response for a non-existent file."""
    print("\n" + "=" * 60)
    print("TEST: File Not Found Error")
    print("=" * 60)

    server_addr = (SERVER_HOST, SERVER_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    # Handshake
    command = "DOWNLOAD:nonexistent_file.xyz"
    syn_pkt = pack_packet(MSG_SYN, 0, 0, command.encode())
    sock.sendto(syn_pkt, server_addr)
    print("[TEST] Sent SYN for non-existent file")

    data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
    r_type, r_sid, r_seq, r_payload = unpack_packet(data)
    assert r_type == MSG_SYN_ACK, f"Expected SYN-ACK, got {msg_name(r_type)}"
    session_id = r_sid
    print(f"[TEST] Received SYN-ACK, session={session_id}")

    ack_pkt = pack_packet(MSG_ACK, session_id, 0)
    sock.sendto(ack_pkt, server_addr)
    print("[TEST] Sent ACK – handshake complete")

    # Expect an ERROR packet
    data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
    r_type, r_sid, r_seq, r_payload = unpack_packet(data)
    assert r_type == MSG_ERROR, f"Expected ERROR, got {msg_name(r_type)}"
    error_msg = r_payload.decode("utf-8", errors="replace")
    print(f"[TEST] Received ERROR: \"{error_msg}\"")
    assert "not found" in error_msg.lower(), f"Error message doesn't mention 'not found'"

    # Termination
    fin_pkt = pack_packet(MSG_FIN, session_id, 0)
    sock.sendto(fin_pkt, server_addr)
    data, addr = sock.recvfrom(HEADER_SIZE + CHUNK_SIZE + 256)
    r_type, r_sid, r_seq, r_payload = unpack_packet(data)
    assert r_type == MSG_FIN_ACK, f"Expected FIN-ACK, got {msg_name(r_type)}"
    print("[TEST] FIN/FIN-ACK exchange complete")
    print(f"[TEST] [OK] PASS – File not found error handled correctly")

    sock.close()


def main():
    print("=" * 60)
    print("RUDP Protocol – Automated Test Suite")
    print("=" * 60)

    # Start server in a background thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1)  # Give server time to start

    passed = 0
    failed = 0
    tests = [test_download, test_upload, test_file_not_found]

    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"[TEST] [X] FAIL – {test_func.__name__}: {e}")
            failed += 1
        time.sleep(0.5)  # Brief pause between tests

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
