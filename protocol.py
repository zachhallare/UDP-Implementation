"""
protocol.py - RUDP Protocol Message Definitions and Utilities.

Defines the binary message format, packing/unpacking routines, CRC-16
checksum computation, and shared constants used by both the client and
server in the Reliable UDP (RUDP) protocol.

Header Layout (13 bytes total):
  ┌──────────┬────────────┬──────────┬─────────────┬──────────┐
  │ msg_type │ session_id │  seq_num │ payload_len │ checksum │
  │  1 byte  │  4 bytes   │ 4 bytes  │   2 bytes   │ 2 bytes  │
  └──────────┴────────────┴──────────┴─────────────┴──────────┘
"""

import struct

# ─── Header Format ────────────────────────────────────────────────────
# B = unsigned char  (1 byte)  ->  msg_type
# I = unsigned int   (4 bytes) ->  session_id
# I = unsigned int   (4 bytes) ->  seq_num
# H = unsigned short (2 bytes) ->  payload_len
# H = unsigned short (2 bytes) ->  checksum
HEADER_FORMAT = "!BIIHH"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 13 bytes

# ─── Message Types ────────────────────────────────────────────────────
MSG_SYN     = 0   # Session initiation
MSG_SYN_ACK = 1   # Session acknowledgement
MSG_ACK     = 2   # General acknowledgement
MSG_DATA    = 3   # Data payload
MSG_FIN     = 4   # Connection termination request
MSG_FIN_ACK = 5   # Connection termination acknowledgement
MSG_ERROR   = 6   # Error notification

# Human-readable names (for logging)
MSG_NAMES = {
    MSG_SYN:     "SYN",
    MSG_SYN_ACK: "SYN-ACK",
    MSG_ACK:     "ACK",
    MSG_DATA:    "DATA",
    MSG_FIN:     "FIN",
    MSG_FIN_ACK: "FIN-ACK",
    MSG_ERROR:   "ERROR",
}


def msg_name(msg_type: int) -> str:
    """Return the human-readable name for a message type."""
    return MSG_NAMES.get(msg_type, f"UNKNOWN({msg_type})")


# ─── CRC-16 Checksum (CRC-16/CCITT-FALSE) ────────────────────────────
def compute_checksum(data: bytes) -> int:
    """
    Compute a CRC-16/CCITT-FALSE checksum over *data*.
    Returns an unsigned 16-bit integer.
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


# ─── Packet Packing ──────────────────────────────────────────────────
def pack_packet(msg_type: int, session_id: int, seq_num: int,
                payload: bytes = b"") -> bytes:
    """
    Build a complete RUDP packet (header + payload) with a valid checksum.

    Parameters
    ----------
    msg_type   : int   – One of the MSG_* constants.
    session_id : int   – 32-bit session identifier.
    seq_num    : int   – 32-bit sequence number.
    payload    : bytes – Payload data (may be empty).

    Returns
    -------
    bytes – The wire-ready packet.
    """
    payload_len = len(payload)

    # Pack header with checksum field set to 0 for calculation
    header_no_crc = struct.pack(HEADER_FORMAT, msg_type, session_id,
                                seq_num, payload_len, 0)
    raw = header_no_crc + payload

    # Compute checksum over entire packet (header + payload, checksum=0)
    crc = compute_checksum(raw)

    # Re-pack header with the real checksum
    header = struct.pack(HEADER_FORMAT, msg_type, session_id,
                         seq_num, payload_len, crc)
    return header + payload


# ─── Packet Unpacking ────────────────────────────────────────────────
class ChecksumError(Exception):
    """Raised when a received packet fails checksum verification."""
    pass


class MalformedPacketError(Exception):
    """Raised when a received packet is too short or structurally invalid."""
    pass


def unpack_packet(data: bytes):
    """
    Parse and validate a raw RUDP packet.

    Parameters
    ----------
    data : bytes – Raw bytes received from the network.

    Returns
    -------
    tuple : (msg_type, session_id, seq_num, payload)

    Raises
    ------
    MalformedPacketError – If the packet is shorter than HEADER_SIZE.
    ChecksumError        – If the checksum does not match.
    """
    if len(data) < HEADER_SIZE:
        raise MalformedPacketError(
            f"Packet too short: {len(data)} bytes (need >= {HEADER_SIZE})")

    # Unpack header fields
    msg_type, session_id, seq_num, payload_len, recv_crc = struct.unpack(
        HEADER_FORMAT, data[:HEADER_SIZE])

    payload = data[HEADER_SIZE:HEADER_SIZE + payload_len]

    # Verify payload length
    if len(payload) != payload_len:
        raise MalformedPacketError(
            f"Payload length mismatch: header says {payload_len}, "
            f"got {len(payload)}")

    # Verify checksum: zero out checksum field, recompute
    header_no_crc = struct.pack(HEADER_FORMAT, msg_type, session_id,
                                seq_num, payload_len, 0)
    raw_for_crc = header_no_crc + payload
    expected_crc = compute_checksum(raw_for_crc)

    if recv_crc != expected_crc:
        raise ChecksumError(
            f"Checksum mismatch: received 0x{recv_crc:04X}, "
            f"expected 0x{expected_crc:04X}")

    return msg_type, session_id, seq_num, payload
