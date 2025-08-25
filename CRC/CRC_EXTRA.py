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

hex_data = bytes.fromhex(
    # header without magic flag
    "20 00 00 9d ff be 4c 00 00" +
    # payload (32 bytes)
    "00 00 80 bf 00 00 00 00 00 00 00 00" +
    "00 00 c0 7f 00 00 c0 7f 00 00 c0 7f" +
    "1e b2 a0 41 16 00 01 01"
)

crc = x25_crc(hex_data, 152)
print(f"the True CRC Checksum is: {hex(crc)}")
