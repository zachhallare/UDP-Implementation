"""
protocol.py - RUDP Protocol: Configuration, Message Definitions, and Utilities.

Contains all configuration constants, binary message format, packing/unpacking
routines, CRC-16 checksum computation, and XOR encryption/HMAC authentication
used by both the client and server in the Reliable UDP (RUDP) protocol.

Header Layout (13 bytes total):
  +----------+------------+----------+-------------+----------+
  | msg_type | session_id |  seq_num | payload_len | checksum |
  |  1 byte  |  4 bytes   | 4 bytes  |   2 bytes   | 2 bytes  |
  +----------+------------+----------+-------------+----------+

@authors Zach Benedict Hallare & Nathan Laborada
@since February 2025
"""

import struct
import hmac
import hashlib

# ===================================================================
# Configuration Parameters
# ===================================================================

SERVER_HOST      = "127.0.0.1"     # Server listen address
SERVER_PORT      = 12345           # Server listen port
CHUNK_SIZE       = 1024            # Max payload bytes per DATA packet
TIMEOUT          = 2.0             # Socket timeout in seconds
MAX_RETRIES      = 5               # Max retransmissions before giving up
SERVER_FILES_DIR = "server_files"  # Directory for server-side files

# Simulated packet loss (for testing retransmission)
SIMULATE_LOSS    = False           # Set True to randomly drop packets
LOSS_PROBABILITY = 0.3             # Drop probability (0.0 - 1.0)

# Shared secret key for encryption and authentication.
# Both client and server use the same key.
SHARED_SECRET = b"rudp-secret-key-2025"

# ===================================================================
# Header Format Constants
# ===================================================================

# B = unsigned char  (1 byte)  -> msg_type
# I = unsigned int   (4 bytes) -> session_id
# I = unsigned int   (4 bytes) -> seq_num
# H = unsigned short (2 bytes) -> payload_len
# H = unsigned short (2 bytes) -> checksum
HEADER_FORMAT = "!BIIHH"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # 13 bytes

# HMAC-SHA256 digest appended to every packet
HMAC_SIZE = 32

# ===================================================================
# Message Type Constants
# ===================================================================

MSG_SYN     = 0  # Session initiation
MSG_SYN_ACK = 1  # Session acknowledgement
MSG_ACK     = 2  # General acknowledgement
MSG_DATA    = 3  # Data payload
MSG_FIN     = 4  # Connection termination request
MSG_FIN_ACK = 5  # Connection termination acknowledgement
MSG_ERROR   = 6  # Error notification

# Human-readable message names for logging
MSG_NAMES = {
    MSG_SYN:     "SYN",
    MSG_SYN_ACK: "SYN-ACK",
    MSG_ACK:     "ACK",
    MSG_DATA:    "DATA",
    MSG_FIN:     "FIN",
    MSG_FIN_ACK: "FIN-ACK",
    MSG_ERROR:   "ERROR",
}


def msg_name(msg_type):
    """
    Return the human-readable name for a message type constant.

    @param msg_type: integer message type (one of MSG_* constants)
    @return: string name of the message type, or "UNKNOWN(n)" if not recognized
    """
    return MSG_NAMES.get(msg_type, f"UNKNOWN({msg_type})")


# ===================================================================
# XOR Encryption
# ===================================================================

def xor_encrypt(data, key):
    """
    Encrypt or decrypt data using repeating-key XOR.
    XOR is its own inverse, so the same function encrypts and decrypts.

    @param data: bytes to encrypt/decrypt
    @param key: bytes key for XOR operation
    @return: XOR-encrypted/decrypted bytes
    """
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


# ===================================================================
# HMAC-SHA256 Authentication
# ===================================================================

def compute_hmac(data, key=SHARED_SECRET):
    """
    Compute HMAC-SHA256 digest over the given data using the shared secret.

    @param data: bytes to authenticate
    @param key: bytes secret key (defaults to SHARED_SECRET)
    @return: 32-byte HMAC-SHA256 digest
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(data, received_hmac, key=SHARED_SECRET):
    """
    Verify HMAC-SHA256 of data against a received HMAC digest.
    Uses constant-time comparison to prevent timing attacks.

    @param data: bytes that were authenticated
    @param received_hmac: 32-byte HMAC digest received from the sender
    @param key: bytes secret key (defaults to SHARED_SECRET)
    @return: True if HMAC matches, False otherwise
    """
    expected = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, received_hmac)


# ===================================================================
# CRC-16 Checksum (CRC-16/CCITT-FALSE)
# ===================================================================

def compute_checksum(data):
    """
    Compute a CRC-16/CCITT-FALSE checksum over the given data.

    @param data: bytes to compute checksum over
    @return: unsigned 16-bit integer checksum
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


# ===================================================================
# Packet Packing
# ===================================================================

def pack_packet(msg_type, session_id, seq_num, payload=b""):
    """
    Build a complete RUDP packet: header + encrypted payload + HMAC.

    The payload is XOR-encrypted before being placed into the packet.
    An HMAC-SHA256 digest is appended to the end for authentication.

    Wire format: [13-byte header][encrypted payload][32-byte HMAC]

    @param msg_type: integer message type (one of MSG_* constants)
    @param session_id: 32-bit unsigned session identifier
    @param seq_num: 32-bit unsigned sequence number
    @param payload: bytes payload data (may be empty)
    @return: bytes wire-ready packet with header, encrypted payload, and HMAC
    """
    # Encrypt the payload using XOR cipher
    encrypted_payload = xor_encrypt(payload, SHARED_SECRET) if payload else b""
    payload_len = len(encrypted_payload)

    # Pack header with checksum field set to 0 for CRC calculation
    header_no_crc = struct.pack(HEADER_FORMAT, msg_type, session_id,
                                seq_num, payload_len, 0)
    raw = header_no_crc + encrypted_payload

    # Compute CRC-16 checksum over header + encrypted payload
    crc = compute_checksum(raw)

    # Re-pack header with the real checksum value
    header = struct.pack(HEADER_FORMAT, msg_type, session_id,
                         seq_num, payload_len, crc)
    packet_body = header + encrypted_payload

    # Append HMAC-SHA256 for authentication
    mac = compute_hmac(packet_body)
    return packet_body + mac


# ===================================================================
# Custom Exception Classes
# ===================================================================

class ChecksumError(Exception):
    """Raised when a received packet fails CRC-16 checksum verification."""
    pass


class MalformedPacketError(Exception):
    """Raised when a received packet is too short or structurally invalid."""
    pass


class AuthenticationError(Exception):
    """Raised when a received packet fails HMAC-SHA256 verification."""
    pass


# ===================================================================
# Packet Unpacking
# ===================================================================

def unpack_packet(data):
    """
    Parse and validate a raw RUDP packet received from the network.

    Validation order: HMAC authentication -> CRC-16 checksum -> payload decryption.

    @param data: bytes raw data received from the network
    @return: tuple of (msg_type, session_id, seq_num, payload) where payload
             is already decrypted
    @raises MalformedPacketError: if packet is too short or payload length mismatches
    @raises AuthenticationError: if HMAC-SHA256 verification fails
    @raises ChecksumError: if CRC-16 checksum does not match
    """
    min_size = HEADER_SIZE + HMAC_SIZE
    if len(data) < min_size:
        raise MalformedPacketError(
            f"Packet too short: {len(data)} bytes (need >= {min_size})")

    # Split off the HMAC (last 32 bytes)
    packet_body = data[:-HMAC_SIZE]
    received_mac = data[-HMAC_SIZE:]

    # Step 1: Verify HMAC authentication
    if not verify_hmac(packet_body, received_mac):
        raise AuthenticationError("HMAC verification failed – packet rejected")

    # Step 2: Unpack header fields
    msg_type, session_id, seq_num, payload_len, recv_crc = struct.unpack(
        HEADER_FORMAT, packet_body[:HEADER_SIZE])

    encrypted_payload = packet_body[HEADER_SIZE:HEADER_SIZE + payload_len]

    # Verify payload length matches header field
    if len(encrypted_payload) != payload_len:
        raise MalformedPacketError(
            f"Payload length mismatch: header says {payload_len}, "
            f"got {len(encrypted_payload)}")

    # Step 3: Verify CRC-16 checksum
    header_no_crc = struct.pack(HEADER_FORMAT, msg_type, session_id,
                                seq_num, payload_len, 0)
    raw_for_crc = header_no_crc + encrypted_payload
    expected_crc = compute_checksum(raw_for_crc)

    if recv_crc != expected_crc:
        raise ChecksumError(
            f"Checksum mismatch: received 0x{recv_crc:04X}, "
            f"expected 0x{expected_crc:04X}")

    # Step 4: Decrypt the payload
    payload = xor_encrypt(encrypted_payload, SHARED_SECRET) if encrypted_payload else b""

    return msg_type, session_id, seq_num, payload
