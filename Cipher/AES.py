import pandas as pd
import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import os
import psutil

def aes_gcm_encrypt(flows, key, logfile='./log/AES.txt', cipherfile=None, keyfile=None, labels=None):
    import csv
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024  # MB
    max_mem = mem_before
    cipher_data = []
    start = time.perf_counter()
    for flow in flows:
        plain = flow.encode('utf-8') if isinstance(flow, str) else bytes(flow)
        iv = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ct, tag = cipher.encrypt_and_digest(plain)
        cipher_data.append((iv, ct, tag))
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
        f.write("AES-128-GCM加密实验结果\n")
        f.write(f"样本数量: {len(flows)}\n")
        f.write(f"加密总耗时: {enc_time*1000:.3f} ms\n")
        f.write(f"单包加密平均耗时: {enc_time*1000/len(flows):.3f} ms\n")
        f.write(f"加密前内存占用: {mem_before:.2f} MB\n")
        f.write(f"加密后内存占用: {mem_after:.2f} MB\n")
        f.write(f"加密过程最大内存占用: {max_mem:.2f} MB\n")
        f.write(f"加密峰值内存增量: {max_mem - mem_before:.2f} MB\n")
    print(f'AES-128-GCM加密完成，日志已写入{logfile}')

    # ==== 写入密文文件 ====
    if cipherfile is not None:
        os.makedirs(os.path.dirname(cipherfile), exist_ok=True)
        with open(cipherfile, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            # 如果有label，加label列，否则只写密文
            if labels is not None:
                writer.writerow(['iv', 'ct', 'tag', 'label'])
                for (iv, ct, tag), label in zip(cipher_data, labels):
                    writer.writerow([iv.hex(), ct.hex(), tag.hex(), label])
            else:
                writer.writerow(['iv', 'ct', 'tag'])
                for iv, ct, tag in cipher_data:
                    writer.writerow([iv.hex(), ct.hex(), tag.hex()])
    # ==== 保存密钥 ====
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
            iv = bytes.fromhex(row['iv'])
            ct = bytes.fromhex(row['ct'])
            tag = bytes.fromhex(row['tag'])
            cipher_data.append((iv, ct, tag))
            if 'label' in row:
                labels.append(row['label'])
    if labels:
        return cipher_data, labels
    return cipher_data

def aes_gcm_decrypt(cipher_data, key, logfile='./log/AES.txt'):
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024  # MB
    max_mem = mem_before
    start = time.perf_counter()
    for iv, ct, tag in cipher_data:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plain = cipher.decrypt_and_verify(ct, tag)
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
        f.write("AES-128-GCM解密实验结果\n")
        f.write(f"样本数量: {len(cipher_data)}\n")
        f.write(f"解密总耗时: {dec_time*1000:.3f} ms\n")
        f.write(f"单包解密平均耗时: {dec_time*1000/len(cipher_data):.3f} ms\n")
        f.write(f"解密前内存占用: {mem_before:.2f} MB\n")
        f.write(f"解密后内存占用: {mem_after:.2f} MB\n")
        f.write(f"解密过程最大内存占用: {max_mem:.2f} MB\n")
        f.write(f"解密峰值内存增量: {max_mem - mem_before:.2f} MB\n")
    print(f'AES-128-GCM解密完成，日志已写入{logfile}')

# ====== 示例调用 ======
if __name__ == "__main__":
    df = pd.read_csv('../Data/packet.csv', nrows=1000)
    flows = df['flow_data'].astype(str).tolist()
    labels = df['label'].tolist() if 'label' in df.columns else None
    key = get_random_bytes(16)
    logfile = './log/AES.txt'
    cipherfile = '../Data/AES/Cipher.csv'
    keyfile = '../Data/AES/key.txt'
    cipher_data = aes_gcm_encrypt(flows, key, logfile=logfile, cipherfile=cipherfile, keyfile=keyfile, labels=labels)

