def x25_crc_accumulate(byte, crc):
    tmp = byte ^ (crc & 0xFF)
    tmp ^= (tmp << 4) & 0xFF
    return ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF

def x25_crc(data: bytes, crc_extra: int):
    crc = 0xFFFF
    for b in data:
        crc = x25_crc_accumulate(b, crc)
    crc = x25_crc_accumulate(crc_extra, crc)
    return crc

header = bytes.fromhex("2000000cffbe4b0000")

payload = bytes.fromhex(
    "000080bf0000803f000000000000c07fe88dab1e8ec572fe02713d41c0000101"
)

# Combine header + payload
packet = header + payload

# crc_extra = 152
# # Calculate CRC
# crc = x25_crc(packet, crc_extra)
# print(f" CRC: {hex(crc)}")
'''
b53e
'''
# Verify CRC
crc_final = 0
for crc_extra in range(0, 256):
    crc = x25_crc(packet, crc_extra)
    if crc == 0x28ce:
        crc_final = crc_extra
    else:
        print(f"crc_extra:{crc_extra} CRC: {hex(crc)}")
        print("\n")

print(crc_final)
