import pandas as pd
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
import time
import os
import psutil
import datetime

def arc4_encrypt(flows, key_len=16, logfile='./log/Rabbit_ARC4.txt', cipherfile=None, keyfile=None, labels=None):
    import csv
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024
    max_mem = mem_before
    cipher_data = []
    all_keys = []
    start = time.perf_counter()
    for flow in flows:
        plain = flow.encode('utf-8') if isinstance(flow, str) else bytes(flow)
        key = get_random_bytes(key_len)
        cipher = ARC4.new(key)
        ct = cipher.encrypt(plain)
        cipher_data.append((key, ct))
        all_keys.append(key.hex())
        cur_mem = process.memory_info().rss / 1024 / 1024
        if cur_mem > max_mem:
            max_mem = cur_mem
    end = time.perf_counter()
    enc_time = end - start
    mem_after = process.memory_info().rss / 1024 / 1024

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write(f"\n实验日期与时间: {now}\n")
        f.write("Rabbit(ARC4模拟)流加密实验结果\n")
        f.write(f"样本数量: {len(flows)}\n")
        f.write(f"加密总耗时: {enc_time*1000:.3f} ms\n")
        f.write(f"单包加密平均耗时: {enc_time*1000/len(flows):.3f} ms\n")
        f.write(f"加密前内存占用: {mem_before:.2f} MB\n")
        f.write(f"加密后内存占用: {mem_after:.2f} MB\n")
        f.write(f"加密过程最大内存占用: {max_mem:.2f} MB\n")
        f.write(f"加密峰值内存增量: {max_mem - mem_before:.2f} MB\n")
    print(f'Rabbit(ARC4模拟)流加密完成，日志已写入{logfile}')

    # ==== 写密文和key到csv ====
    if cipherfile is not None:
        os.makedirs(os.path.dirname(cipherfile), exist_ok=True)
        with open(cipherfile, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            if labels is not None:
                writer.writerow(['key', 'ct', 'label'])
                for (key, ct), label in zip(cipher_data, labels):
                    writer.writerow([key.hex(), ct.hex(), label])
            else:
                writer.writerow(['key', 'ct'])
                for key, ct in cipher_data:
                    writer.writerow([key.hex(), ct.hex()])

    # ==== 写所有key到keyfile（可选）====
    if keyfile is not None:
        os.makedirs(os.path.dirname(keyfile), exist_ok=True)
        with open(keyfile, 'w') as kf:
            for k in all_keys:
                kf.write(k + '\n')

    return cipher_data

def arc4_decrypt(cipher_data, logfile='./log/Rabbit_ARC4.txt'):
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024
    max_mem = mem_before
    start = time.perf_counter()
    for key, ct in cipher_data:
        cipher = ARC4.new(key)
        plain = cipher.decrypt(ct)
        cur_mem = process.memory_info().rss / 1024 / 1024
        if cur_mem > max_mem:
            max_mem = cur_mem
    end = time.perf_counter()
    dec_time = end - start
    mem_after = process.memory_info().rss / 1024 / 1024

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write(f"实验日期与时间: {now}\n")
        f.write("Rabbit(ARC4模拟)流解密实验结果\n")
        f.write(f"样本数量: {len(cipher_data)}\n")
        f.write(f"解密总耗时: {dec_time*1000:.3f} ms\n")
        f.write(f"单包解密平均耗时: {dec_time*1000/len(cipher_data):.3f} ms\n")
        f.write(f"解密前内存占用: {mem_before:.2f} MB\n")
        f.write(f"解密后内存占用: {mem_after:.2f} MB\n")
        f.write(f"解密过程最大内存占用: {max_mem:.2f} MB\n")
        f.write(f"解密峰值内存增量: {max_mem - mem_before:.2f} MB\n")
    print(f'Rabbit(ARC4模拟)流解密完成，日志已写入{logfile}')

def load_cipher_csv(cipherfile):
    import csv
    cipher_data = []
    labels = []
    with open(cipherfile, 'r', encoding='utf-8') as cf:
        reader = csv.DictReader(cf)
        for row in reader:
            key = bytes.fromhex(row['key'])
            ct = bytes.fromhex(row['ct'])
            cipher_data.append((key, ct))
            if 'label' in row and row['label'] != '':
                labels.append(row['label'])
    if labels:
        return cipher_data, labels
    return cipher_data

if __name__ == "__main__":
    df = pd.read_csv('../Data/packet.csv', nrows=16000)
    flows = df['flow_data'].astype(str).tolist()
    labels = df['label'].tolist() if 'label' in df.columns else None

    logfile = './log/Rabbit_ARC4.txt'
    cipherfile = '../Data/Rabbit/Cipher.csv'
    keyfile = '../Data/Rabbit/key.txt'

    # 加密并写入文件
    cipher_data = arc4_encrypt(
        flows, key_len=16,
        logfile=logfile,
        # cipherfile=cipherfile,
        # keyfile=keyfile,
        # labels=labels
    )
    #
    # # 从csv读取密文再解密
    # cipher_data_loaded = load_cipher_csv(cipherfile)
    # arc4_decrypt(cipher_data_loaded, logfile=logfile)
