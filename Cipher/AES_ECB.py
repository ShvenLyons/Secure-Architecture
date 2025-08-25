import pandas as pd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import os
import psutil
import datetime

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def aes_ecb_encrypt(flows, key, logfile='./log/AES-ECB.txt', cipherfile=None, keyfile=None, labels=None):
    import csv
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024  # MB
    max_mem = mem_before
    cipher_data = []
    block_size = AES.block_size  # 16
    start = time.perf_counter()
    for flow in flows:
        plain = flow.encode('utf-8') if isinstance(flow, str) else bytes(flow)
        padded = pkcs7_pad(plain, block_size)
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(padded)
        cipher_data.append((ct, len(plain)))  # 保存原文长度用于解密后去填充
        cur_mem = process.memory_info().rss / 1024 / 1024
        if cur_mem > max_mem:
            max_mem = cur_mem
    end = time.perf_counter()
    enc_time = end - start
    mem_after = process.memory_info().rss / 1024 / 1024  # MB

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write(f"\n实验日期与时间: {now}\n")
        f.write("AES-128-ECB加密实验结果\n")
        f.write(f"样本数量: {len(flows)}\n")
        f.write(f"加密总耗时: {enc_time*1000:.3f} ms\n")
        f.write(f"单包加密平均耗时: {enc_time*1000/len(flows):.3f} ms\n")
        f.write(f"加密前内存占用: {mem_before:.2f} MB\n")
        f.write(f"加密后内存占用: {mem_after:.2f} MB\n")
        f.write(f"加密过程最大内存占用: {max_mem:.2f} MB\n")
        f.write(f"加密峰值内存增量: {max_mem - mem_before:.2f} MB\n")
    print(f'AES-128-ECB加密完成，日志已写入{logfile}')

    # ==== 写入密文csv ====
    if cipherfile is not None:
        os.makedirs(os.path.dirname(cipherfile), exist_ok=True)
        with open(cipherfile, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            if labels is not None:
                writer.writerow(['ct', 'orig_len', 'label'])
                for (ct, orig_len), label in zip(cipher_data, labels):
                    writer.writerow([ct.hex(), orig_len, label])
            else:
                writer.writerow(['ct', 'orig_len'])
                for ct, orig_len in cipher_data:
                    writer.writerow([ct.hex(), orig_len])

    # ==== 写密钥 ====
    if keyfile is not None:
        os.makedirs(os.path.dirname(keyfile), exist_ok=True)
        with open(keyfile, 'w') as kf:
            kf.write(key.hex())

    return cipher_data

def load_ecb_cipher_csv(cipherfile):
    import csv
    cipher_data = []
    labels = []
    with open(cipherfile, 'r', encoding='utf-8') as cf:
        reader = csv.DictReader(cf)
        for row in reader:
            ct = bytes.fromhex(row['ct'])
            orig_len = int(row['orig_len'])
            cipher_data.append((ct, orig_len))
            if 'label' in row and row['label'] != '':
                labels.append(row['label'])
    if labels:
        return cipher_data, labels
    return cipher_data

def aes_ecb_decrypt(cipher_data, key, logfile='./log/AES-ECB.txt'):
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024  # MB
    max_mem = mem_before
    block_size = AES.block_size
    start = time.perf_counter()
    for ct, orig_len in cipher_data:
        cipher = AES.new(key, AES.MODE_ECB)
        padded = cipher.decrypt(ct)
        plain = pkcs7_unpad(padded)
        assert len(plain) == orig_len  # 验证解密正确
        cur_mem = process.memory_info().rss / 1024 / 1024
        if cur_mem > max_mem:
            max_mem = cur_mem
    end = time.perf_counter()
    dec_time = end - start
    mem_after = process.memory_info().rss / 1024 / 1024  # MB

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write(f"实验日期与时间: {now}\n")
        f.write("AES-128-ECB解密实验结果\n")
        f.write(f"样本数量: {len(cipher_data)}\n")
        f.write(f"解密总耗时: {dec_time*1000:.3f} ms\n")
        f.write(f"单包解密平均耗时: {dec_time*1000/len(cipher_data):.3f} ms\n")
        f.write(f"解密前内存占用: {mem_before:.2f} MB\n")
        f.write(f"解密后内存占用: {mem_after:.2f} MB\n")
        f.write(f"解密过程最大内存占用: {max_mem:.2f} MB\n")
        f.write(f"解密峰值内存增量: {max_mem - mem_before:.2f} MB\n")
    print(f'AES-128-ECB解密完成，日志已写入{logfile}')

# ====== 示例调用 ======
if __name__ == "__main__":
    df = pd.read_csv('../Data/packet.csv', nrows=16000)
    flows = df['flow_data'].astype(str).tolist()
    labels = df['label'].tolist() if 'label' in df.columns else None
    key = get_random_bytes(16)
    logfile = './log/AES-ECB.txt'
    cipherfile = '../Data/AES_ECB/Cipher.csv'
    keyfile = '../Data/AES_ECB/key.txt'
    # 加密并保存
    cipher_data = aes_ecb_encrypt(
        flows, key,
        logfile=logfile,
        cipherfile=cipherfile,
        keyfile=keyfile,
        labels=labels
    )
    # 读取密文
    # cipher_data_loaded, loaded_labels = load_ecb_cipher_csv(cipherfile)
    # 解密
    # aes_ecb_decrypt(cipher_data_loaded, key, logfile=logfile)
