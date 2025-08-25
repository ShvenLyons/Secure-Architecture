import sys
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox,
    QTextEdit, QHBoxLayout, QDialog, QLineEdit, QMessageBox, QCheckBox
)
from encrypt_utils import *

class PlaintextEncryptDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Encryption and Decryption Window")
        layout = QVBoxLayout()
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("Input Plaintext...")
        layout.addWidget(QLabel("Plaintext Accept"))
        layout.addWidget(self.input_edit)

        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("Manually enter the key (hex) or Randomly")
        layout.addWidget(QLabel("Key (hex)）"))
        layout.addWidget(self.key_edit)

        self.algo_combo = QComboBox()
        self.algo_combo.addItems([
            "AES-128-GCM", "AES-128-CTR", "ChaCha20", "ASCON-128", "XTEA-OFB",
            "DMAV", "Navid", "ARC4", "Speck-CTR"
        ])
        layout.addWidget(QLabel("Choose Cipher"))
        layout.addWidget(self.algo_combo)

        btns = QHBoxLayout()
        self.encrypt_btn = QPushButton("To Encrypt")
        btns.addWidget(self.encrypt_btn)
        layout.addLayout(btns)

        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        layout.addWidget(QLabel("Output"))
        layout.addWidget(self.output_edit)

        self.setLayout(layout)

        self.encrypt_btn.clicked.connect(self.do_encrypt)

    def do_encrypt(self):
        algo = self.algo_combo.currentText()
        text = self.input_edit.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "WRONG", "Empty Plaintext！")
            return
        key_hex = self.key_edit.text().strip()
        import os
        from Crypto.Random import get_random_bytes

        if algo in ["AES-128-GCM", "AES-128-CTR", "ASCON-128"]:
            key_len = 16
        elif algo == "ChaCha20":
            key_len = 32
        else:
            key_len = 16
        key = bytes.fromhex(key_hex) if key_hex else (os.urandom(key_len) if algo == "ASCON-128" else get_random_bytes(key_len))
        if key_hex and len(key) != key_len:
            QMessageBox.warning(self, "WRONG", f"Length of Key MUST BE {key_len*2} bites hex string！")
            return

        try:
            flows = [text]
            if algo == "AES-128-GCM":
                cipher_data = aes_gcm_encrypt(flows, key)
                iv, ct, tag = cipher_data[0]
                self.output_edit.setPlainText(f"IV:{iv.hex()}\nCT:{ct.hex()}\nTAG:{tag.hex()}\nKEY:{key.hex()}")
            elif algo == "AES-128-CTR":
                cipher_data = aes_ctr_encrypt(flows, key)
                nonce, ct = cipher_data[0]
                self.output_edit.setPlainText(f"NONCE:{nonce.hex()}\nCT:{ct.hex()}\nKEY:{key.hex()}")
            elif algo == "ChaCha20":
                cipher_data = chacha20_encrypt(flows, key)
                nonce, ct = cipher_data[0]
                self.output_edit.setPlainText(f"NONCE:{nonce.hex()}\nCT:{ct.hex()}\nKEY:{key.hex()}")
            elif algo == "ASCON-128":
                cipher_data = ascon_encrypt(flows, key)
                nonce, ct = cipher_data[0]
                self.output_edit.setPlainText(f"NONCE:{nonce.hex()}\nCT:{ct.hex()}\nKEY:{key.hex()}")
            elif algo == "XTEA-OFB":
                cipher_data = xtea_ofb_encrypt(flows)
                key2, iv, ct, orig_len = cipher_data[0]
                self.output_edit.setPlainText(f"KEY:{key2.hex()}\nIV:{iv.hex()}\nCT:{ct.hex()}")
            elif algo == "DMAV(XOR)":
                cipher_data = dmav_xor_encrypt(flows)
                key2, ct, orig_len = cipher_data[0]
                self.output_edit.setPlainText(f"KEY:{key2.hex()}\nCT:{ct.hex()}")
            elif algo == "Navid(XOR)":
                cipher_data = navid_encrypt(flows)
                key2, ct, orig_len = cipher_data[0]
                self.output_edit.setPlainText(f"KEY:{key2.hex()}\nCT:{ct.hex()}")
            elif algo == "ARC4(Rabbit模拟)":
                cipher_data = arc4_encrypt(flows)
                key2, ct = cipher_data[0]
                self.output_edit.setPlainText(f"KEY:{key2.hex()}\nCT:{ct.hex()}")
            elif algo == "Speck-CTR":
                cipher_data = speck_ctr_encrypt(flows)
                key2, iv, ct, orig_len = cipher_data[0]
                self.output_edit.setPlainText(f"KEY:{key2.hex()}\nIV:{iv.hex()}\nCT:{ct.hex()}")
        except Exception as e:
            QMessageBox.warning(self, "FAIL", str(e))

class CryptoGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Cipher Comparison Proxy')
        self.setGeometry(200, 200, 540, 400)
        layout = QVBoxLayout()
        self.info_label = QLabel("Choose Cipher, Choose Operation，Press "GO"。Log file will write in ./log/")
        layout.addWidget(self.info_label)

        self.combo = QComboBox()
        self.combo.addItems([
            "AES-128-GCM", "AES-128-CTR", "ChaCha20", "ASCON-128", "XTEA-OFB",
            "DMAV", "Navid", "ARC4", "Speck-CTR"
        ])
        layout.addWidget(self.combo)

        btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton('Encrypt')
        self.decrypt_btn = QPushButton('Decrypt')
        self.onekey_btn = QPushButton('Encrypt & Decrypt')
        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.addWidget(self.decrypt_btn)
        btn_layout.addWidget(self.onekey_btn)
        layout.addLayout(btn_layout)

        # 保存密文密钥选项
        self.save_cipher_checkbox = QCheckBox("Save encrypted messages and keys in File")
        self.save_cipher_checkbox.setChecked(False)
        layout.addWidget(self.save_cipher_checkbox)

        self.open_plain_window_btn = QPushButton('Encryption and Decryption Window')
        layout.addWidget(self.open_plain_window_btn)
        self.open_plain_window_btn.clicked.connect(self.open_plain_window)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.setLayout(layout)

        self.encrypt_btn.clicked.connect(self.encrypt_clicked)
        self.decrypt_btn.clicked.connect(self.decrypt_clicked)
        self.onekey_btn.clicked.connect(self.onekey_clicked)

        self.df = pd.read_csv('./Data/packet.csv', nrows=1000)
        self.flows = self.df['flow_data'].astype(str).tolist()
        self.last_cipher_data = None
        self.last_key = None

        # 各算法保存文件路径
        self.cipherfile_paths = {
            "AES-128-GCM": "./Data/AES/Cipher.csv",
            "AES-128-CTR": "./Data/AES_CTR/Cipher.csv",
            "ChaCha20": "./Data/ChaCha20/Cipher.csv",
            "ASCON-128": "./Data/ASCON/Cipher.csv",
            "XTEA-OFB": "./Data/XTEA/Cipher.csv",
            "DMAV(XOR)": "./Data/DMAV/Cipher.csv",
            "Navid(XOR)": "./Data/Navid/Cipher.csv",
            "ARC4(Rabbit模拟)": "./Data/Rabbit/Cipher.csv",
            "Speck-CTR": "./Data/Speck/Cipher.csv",
        }
        self.keyfile_paths = {
            "AES-128-GCM": "./Data/AES/key.txt",
            "AES-128-CTR": "./Data/AES_CTR/key.txt",
            "ChaCha20": "./Data/ChaCha20/key.txt",
            "ASCON-128": "./Data/ASCON/key.txt",
            "XTEA-OFB": "./Data/XTEA/key.txt",
            "DMAV(XOR)": "./Data/DMAV/key.txt",
            "Navid(XOR)": "./Data/Navid/key.txt",
            "ARC4(Rabbit模拟)": "./Data/Rabbit/key.txt",
            "Speck-CTR": "./Data/Speck/key.txt",
        }

    def encrypt_clicked(self):
        algo = self.combo.currentText()
        self.log_area.append(f'Start Encrypt（Cipher：{algo}）...')
        key, cipher_data = None, None
        cipherfile = self.cipherfile_paths.get(algo, None) if self.save_cipher_checkbox.isChecked() else None
        keyfile = self.keyfile_paths.get(algo, None) if self.save_cipher_checkbox.isChecked() else None
        try:
            key, cipher_data = self._do_encrypt(algo, cipherfile, keyfile)
            self.last_cipher_data = cipher_data
            self.last_key = key
            self.log_area.append("Encryption Finish，LOG FILE in ./log/")
            if self.save_cipher_checkbox.isChecked():
                self.log_area.append(f"Message and KEY are in：\n{cipherfile}\n{keyfile}")
        except Exception as e:
            self.log_area.append(f"FAIL: {e}")

    def decrypt_clicked(self):
        algo = self.combo.currentText()
        self.log_area.append(f'Start Decrypt（Cipher：{algo}）...')
        try:
            if self.last_cipher_data is None:
                self.log_area.append("Encrypt First or Move encrypted message in")
                return
            self._do_decrypt(algo, self.last_cipher_data, self.last_key)
            self.log_area.append("Decryption Finish，LOG FILE in ./log/")
        except Exception as e:
            self.log_area.append(f"FAIL: {e}")

    def onekey_clicked(self):
        self.log_area.append('Start Encrypt and Decrypt...')
        algos = [
            "AES-128-GCM", "AES-128-CTR", "ChaCha20", "ASCON-128", "XTEA-OFB",
            "DMAV", "Navid", "ARC4", "Speck-CTR"
        ]
        for algo in algos:
            self.log_area.append(f'[{algo}] encrypting...')
            cipherfile = self.cipherfile_paths.get(algo, None) if self.save_cipher_checkbox.isChecked() else None
            keyfile = self.keyfile_paths.get(algo, None) if self.save_cipher_checkbox.isChecked() else None
            try:
                key, cipher_data = self._do_encrypt(algo, cipherfile, keyfile)
                self.log_area.append(f'[{algo}] encryption finish')
                if self.save_cipher_checkbox.isChecked():
                    self.log_area.append(f'[{algo}] message and KEY in：\n{cipherfile}\n{keyfile}')
                self.log_area.append(f'[{algo}] decrypting...')
                self._do_decrypt(algo, cipher_data, key)
                self.log_area.append(f'[{algo}] decryption finish')
            except Exception as e:
                self.log_area.append(f'[{algo}] FAIL: {e}')
        self.log_area.append('FINISH ALL, LOG FILE IN ./log/Record.txt')

    def _do_encrypt(self, algo, cipherfile=None, keyfile=None):
        import os
        from Crypto.Random import get_random_bytes
        key, cipher_data = None, None
        labels = self.df['label'].tolist() if 'label' in self.df.columns else None
        if algo == "AES-128-GCM":
            key = get_random_bytes(16)
            cipher_data = aes_gcm_encrypt(self.flows, key, logfile='./log/Record.txt',
                                          cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        elif algo == "AES-128-CTR":
            key = get_random_bytes(16)
            cipher_data = aes_ctr_encrypt(self.flows, key, logfile='./log/Record.txt',
                                          cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        elif algo == "ChaCha20":
            key = get_random_bytes(32)
            cipher_data = chacha20_encrypt(self.flows, key, logfile='./log/Record.txt',
                                           cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        elif algo == "ASCON-128":
            key = os.urandom(16)
            cipher_data = ascon_encrypt(self.flows, key, logfile='./log/Record.txt',
                                        cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        elif algo == "XTEA-OFB":
            cipher_data = xtea_ofb_encrypt(self.flows, logfile='./log/Record.txt',
                                           cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        elif algo == "DMAV":
            cipher_data = dmav_xor_encrypt(self.flows, logfile='./log/Record.txt',
                                           cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        elif algo == "Navid":
            cipher_data = navid_encrypt(self.flows, logfile='./log/Record.txt',
                                        cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        elif algo == "ARC4":
            cipher_data = arc4_encrypt(self.flows, logfile='./log/Record.txt',
                                       cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        elif algo == "Speck-CTR":
            cipher_data = speck_ctr_encrypt(self.flows, logfile='./log/Record.txt',
                                            cipherfile=cipherfile, keyfile=keyfile, labels=labels)
        return key, cipher_data

    def _do_decrypt(self, algo, cipher_data, key):
        if algo == "AES-128-GCM":
            aes_gcm_decrypt(cipher_data, key, logfile='./log/Record.txt')
        elif algo == "AES-128-CTR":
            aes_ctr_decrypt(cipher_data, key, logfile='./log/Record.txt')
        elif algo == "ChaCha20":
            chacha20_decrypt(cipher_data, key, logfile='./log/Record.txt')
        elif algo == "ASCON-128":
            ascon_decrypt(cipher_data, key, logfile='./log/Record.txt')
        elif algo == "XTEA-OFB":
            xtea_ofb_decrypt(cipher_data, logfile='./log/Record.txt')
        elif algo == "DMAV":
            dmav_xor_decrypt(cipher_data, logfile='./log/Record.txt')
        elif algo == "Navid)":
            navid_decrypt(cipher_data, logfile='./log/Record.txt')
        elif algo == "ARC4)":
            arc4_decrypt(cipher_data, logfile='./log/Record.txt')
        elif algo == "Speck-CTR":
            speck_ctr_decrypt(cipher_data, logfile='./log/Record.txt')

    def open_plain_window(self):
        dlg = PlaintextEncryptDialog(self)
        dlg.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CryptoGUI()
    window.show()
    sys.exit(app.exec_())

