"""
config.py - Configuration parameters for the RUDP protocol.

All tuneable constants for the reliable UDP protocol are defined here.
Toggle SIMULATE_LOSS to True and adjust LOSS_PROBABILITY to test
retransmission behaviour without external network tools.
"""

# ─── Network Settings ────────────────────────────────────────────────
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345

# ─── Transfer Settings ───────────────────────────────────────────────
CHUNK_SIZE = 1024          # Max payload bytes per DATA packet
TIMEOUT    = 2.0           # Socket timeout in seconds
MAX_RETRIES = 5            # Max retransmissions before giving up

# ─── Directories ─────────────────────────────────────────────────────
SERVER_FILES_DIR = "server_files"   # Directory for server-side files

# ─── Simulated Packet Loss (for testing) ─────────────────────────────
SIMULATE_LOSS      = False   # Set to True to randomly drop packets
LOSS_PROBABILITY   = 0.3     # Probability of dropping a packet (0.0–1.0)
