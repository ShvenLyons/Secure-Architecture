import pandas as pd
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import time
import os
import psutil
import datetime

def chacha20_encrypt(flows, key, logfile='./log/ChaCha20.txt', cipherfile=None, keyfile=None, labels=None):
    import csv
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024  # MB
    max_mem = mem_before
    nonce_len = 8
    cipher_data = []
    start = time.perf_counter()
    for flow in flows:
        plain = flow.encode('utf-8') if isinstance(flow, str) else bytes(flow)
        nonce = get_random_bytes(nonce_len)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ct = cipher.encrypt(plain)
        cipher_data.append((nonce, ct))
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
        f.write("ChaCha20加密实验结果\n")
        f.write(f"样本数量: {len(flows)}\n")
        f.write(f"加密总耗时: {enc_time*1000:.3f} ms\n")
        f.write(f"单包加密平均耗时: {enc_time*1000/len(flows):.3f} ms\n")
        f.write(f"加密前内存占用: {mem_before:.2f} MB\n")
        f.write(f"加密后内存占用: {mem_after:.2f} MB\n")
        f.write(f"加密过程最大内存占用: {max_mem:.2f} MB\n")
        f.write(f"加密峰值内存增量: {max_mem - mem_before:.2f} MB\n")
    print(f'ChaCha20加密完成，日志已写入{logfile}')

    # ==== 写入密文csv ====
    if cipherfile is not None:
        os.makedirs(os.path.dirname(cipherfile), exist_ok=True)
        with open(cipherfile, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            if labels is not None:
                writer.writerow(['nonce', 'ct', 'label'])
                for (nonce, ct), label in zip(cipher_data, labels):
                    writer.writerow([nonce.hex(), ct.hex(), label])
            else:
                writer.writerow(['nonce', 'ct'])
                for nonce, ct in cipher_data:
                    writer.writerow([nonce.hex(), ct.hex()])

    # ==== 写密钥 ====
    if keyfile is not None:
        os.makedirs(os.path.dirname(keyfile), exist_ok=True)
        with open(keyfile, 'w') as kf:
            kf.write(key.hex())

    return cipher_data

def load_cipher_csv(cipherfile):
    import csv
    cipher_data = []
    labels = []
    with open(cipherfile, 'r', encoding='utf-8') as cf:
        reader = csv.DictReader(cf)
        for row in reader:
            nonce = bytes.fromhex(row['nonce'])
            ct = bytes.fromhex(row['ct'])
            cipher_data.append((nonce, ct))
            if 'label' in row and row['label'] != '':
                labels.append(row['label'])
    if labels:
        return cipher_data, labels
    return cipher_data

def chacha20_decrypt(cipher_data, key, logfile='./log/ChaCha20.txt'):
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024  # MB
    max_mem = mem_before
    start = time.perf_counter()
    for nonce, ct in cipher_data:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plain = cipher.decrypt(ct)
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
        f.write("ChaCha20解密实验结果\n")
        f.write(f"样本数量: {len(cipher_data)}\n")
        f.write(f"解密总耗时: {dec_time*1000:.3f} ms\n")
        f.write(f"单包解密平均耗时: {dec_time*1000/len(cipher_data):.3f} ms\n")
        f.write(f"解密前内存占用: {mem_before:.2f} MB\n")
        f.write(f"解密后内存占用: {mem_after:.2f} MB\n")
        f.write(f"解密过程最大内存占用: {max_mem:.2f} MB\n")
        f.write(f"解密峰值内存增量: {max_mem - mem_before:.2f} MB\n")
    print(f'ChaCha20解密完成，日志已写入{logfile}')

if __name__ == "__main__":
    df = pd.read_csv('../Data/packet.csv', nrows=16000)
    flows = df['flow_data'].astype(str).tolist()
    labels = df['label'].tolist() if 'label' in df.columns else None
    key = get_random_bytes(32)

    logfile = './log/ChaCha20.txt'
    cipherfile = '../Data/ChaCha20/Cipher.csv'
    keyfile = '../Data/ChaCha20/key.txt'

    # 加密并保存
    cipher_data = chacha20_encrypt(
        flows, key,
        logfile=logfile,
        cipherfile=cipherfile,
        keyfile=keyfile,
        labels=labels
    )
    #
    # # ======= 读取csv+key进行解密 =======
    # cipher_data_loaded = load_cipher_csv(cipherfile)
    # with open(keyfile, 'r') as f:
    #     key_loaded = bytes.fromhex(f.read().strip())
    # chacha20_decrypt(cipher_data_loaded, key_loaded, logfile)


