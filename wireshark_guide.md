# Wireshark Guide for RUDP Packet Tracing

This guide explains how to use **Wireshark** to capture and analyze RUDP packets from this project. Your professor will likely ask you to demonstrate packet tracing, so follow these steps.

---

## 1. Install Wireshark

Download and install from [wireshark.org](https://www.wireshark.org/download.html). During installation on Windows, make sure to install **Npcap** (required for packet capture).

---

## 2. Capture on the Loopback Interface

Since the client and server both run on `127.0.0.1`, you need to capture on the **loopback** adapter.

### Windows
1. Open Wireshark
2. In the interface list, look for **"Adapter for loopback traffic capture"** or **"Npcap Loopback Adapter"**
3. Double-click it to start capturing

> **Note:** If you don't see a loopback adapter, reinstall Npcap with the "Support raw 802.11 traffic" and "Install Npcap in WinPCap API-compatible Mode" options checked.

### macOS / Linux
1. Open Wireshark
2. Select the **"lo"** (loopback) interface
3. Click the blue shark fin button to start capturing

---

## 3. Display Filter

Once capturing, apply this **display filter** to show only our RUDP packets:

```
udp.port == 12345
```

Type this in the filter bar at the top and press Enter. This filters out all other traffic and shows only our protocol's packets.

---

## 4. Run the Server and Client

With Wireshark capturing, open two terminals:

**Terminal 1 – Server:**
```
python server.py
```

**Terminal 2 – Client:**
```
python client.py
```

Then issue a command in the client:
```
rudp> download test.txt
```

You'll see packets appear in Wireshark in real-time.

---

## 5. Reading the Packets in Wireshark

Each row in Wireshark is one UDP datagram. Click on a packet to inspect it.

### What You'll See

| Wireshark Column | What It Shows |
|---|---|
| **No.** | Packet number in the capture |
| **Time** | Timestamp |
| **Source** | `127.0.0.1` (both sides are localhost) |
| **Destination** | `127.0.0.1` |
| **Protocol** | `UDP` |
| **Length** | Total UDP datagram size |
| **Info** | Source port → Destination port, length |

### Identifying Packet Direction

- **Client → Server**: Destination port is `12345`
- **Server → Client**: Source port is `12345`

---

## 6. Inspecting the RUDP Header (Hex View)

Click on any packet, then look at the **bottom pane** (hex dump). The UDP payload starts after the UDP header. Our RUDP header is the first **13 bytes** of the UDP payload:

```
Byte 0:        msg_type     (1 byte)
Bytes 1-4:     session_id   (4 bytes, big-endian)
Bytes 5-8:     seq_num      (4 bytes, big-endian)
Bytes 9-10:    payload_len  (2 bytes, big-endian)
Bytes 11-12:   checksum     (2 bytes, big-endian)
Bytes 13+:     encrypted payload (payload_len bytes)
Last 32 bytes: HMAC-SHA256  (authentication tag)
```

### Example: Identifying Message Types in Hex

| First Byte (Hex) | Message Type |
|---|---|
| `00` | SYN |
| `01` | SYN-ACK |
| `02` | ACK |
| `03` | DATA |
| `04` | FIN |
| `05` | FIN-ACK |
| `06` | ERROR |

So if you see a packet where the UDP payload starts with `00`, that's a **SYN** packet.

---

## 7. Tracing a Full Session

For a file **download**, you should see this sequence in Wireshark:

| # | Direction | First Byte | Meaning |
|---|---|---|---|
| 1 | Client → Server | `00` | **SYN** – Client requests download |
| 2 | Server → Client | `01` | **SYN-ACK** – Server accepts, sends session params |
| 3 | Client → Server | `02` | **ACK** – Handshake complete |
| 4 | Server → Client | `03` | **DATA seq=0** – First chunk of file |
| 5 | Client → Server | `02` | **ACK seq=0** – Client acknowledges |
| 6 | Server → Client | `03` | **DATA seq=1** – Second chunk |
| 7 | Client → Server | `02` | **ACK seq=1** – Client acknowledges |
| ... | ... | ... | ... (repeats for each chunk) |
| N-2 | Server → Client | `03` | **DATA seq=N (empty)** – EOF signal |
| N-1 | Client → Server | `02` | **ACK for EOF** |
| N | Client → Server | `04` | **FIN** – Client requests termination |
| N+1 | Server → Client | `05` | **FIN-ACK** – Session terminated |

---

## 8. Verifying Encryption in Wireshark

Since all payloads are XOR-encrypted, you can verify this in Wireshark:

1. Click on a **DATA** packet (first byte = `03`)
2. Look at the hex dump of the UDP payload after byte 13
3. The data will appear as **random/scrambled bytes** — NOT readable text
4. This proves encryption is working

If you compare the encrypted data in Wireshark to what the client actually saves to disk, the saved file will be readable (because the client decrypts it), but Wireshark shows the encrypted version on the wire.

---

## 9. Verifying HMAC Authentication

Each packet's last **32 bytes** are the HMAC-SHA256 digest. In Wireshark:

1. Click on any packet
2. Go to the hex view
3. The last 32 bytes of the UDP payload are the HMAC
4. You can verify the total packet length = 13 (header) + payload_len + 32 (HMAC)

---

## 10. Testing Retransmission in Wireshark

To see retransmission behavior:

1. Set `SIMULATE_LOSS = True` in `protocol.py`
2. Start Wireshark, then run server and client
3. Transfer a file
4. In Wireshark, you'll see **duplicate packets** (same seq_num sent multiple times)
5. The console will show `[SIM] Dropped` messages matching the timeout/retransmit pattern

---

## 11. Useful Wireshark Tips

### Export Packet List
- **File → Export Packet Dissections → As Plain Text** to save a text log of your capture

### Save Capture
- **File → Save As** to save as `.pcapng` file (you can submit this if your prof asks)

### Follow UDP Stream
- Right-click a packet → **Follow → UDP Stream** to see all data exchanged in one session

### Color Coding
- Wireshark color-codes packets. UDP packets are typically light blue.

### Packet Bytes View
- **View → Packet Bytes** if the hex pane is not visible

---

## 12. Quick Cheat Sheet

```
1. Open Wireshark → select Loopback adapter
2. Start capture
3. Apply filter: udp.port == 12345
4. Run python server.py  (Terminal 1)
5. Run python client.py  (Terminal 2)
6. Type: download test.txt
7. Watch the SYN → SYN-ACK → ACK → DATA/ACK → EOF → FIN → FIN-ACK flow
8. Click packets to inspect hex view
9. Stop capture when done (red square button)
10. Save capture: File → Save As → capture.pcapng
```
