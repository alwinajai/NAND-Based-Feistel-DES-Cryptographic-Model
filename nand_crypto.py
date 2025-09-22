"""
Full DES implementation (64-bit block, 16 rounds).
Tkinter GUI (text-only): encryption -> hex output, decryption <- hex input.
Preserves whitespace/newlines in plaintext.

Now with dynamic random key generation (DES odd parity enforced) and buttons:
 - "Random Key" (generate secure key)
 - "Use Test Key" (fill the classic 133457799BBCDFF1)
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
import binascii
import string
import secrets

# ----------------------
# DES TABLES (standard)
# ----------------------

IP = [
 58,50,42,34,26,18,10,2,
 60,52,44,36,28,20,12,4,
 62,54,46,38,30,22,14,6,
 64,56,48,40,32,24,16,8,
 57,49,41,33,25,17,9,1,
 59,51,43,35,27,19,11,3,
 61,53,45,37,29,21,13,5,
 63,55,47,39,31,23,15,7
]

FP = [
 40,8,48,16,56,24,64,32,
 39,7,47,15,55,23,63,31,
 38,6,46,14,54,22,62,30,
 37,5,45,13,53,21,61,29,
 36,4,44,12,52,20,60,28,
 35,3,43,11,51,19,59,27,
 34,2,42,10,50,18,58,26,
 33,1,41,9,49,17,57,25
]

E = [
 32,1,2,3,4,5,
 4,5,6,7,8,9,
 8,9,10,11,12,13,
 12,13,14,15,16,17,
 16,17,18,19,20,21,
 20,21,22,23,24,25,
 24,25,26,27,28,29,
 28,29,30,31,32,1
]

P = [
 16,7,20,21,29,12,28,17,
 1,15,23,26,5,18,31,10,
 2,8,24,14,32,27,3,9,
 19,13,30,6,22,11,4,25
]

PC1 = [
 57,49,41,33,25,17,9,
 1,58,50,42,34,26,18,
 10,2,59,51,43,35,27,
 19,11,3,60,52,44,36,
 63,55,47,39,31,23,15,
 7,62,54,46,38,30,22,
 14,6,61,53,45,37,29,
 21,13,5,28,20,12,4
]

PC2 = [
 14,17,11,24,1,5,
 3,28,15,6,21,10,
 23,19,12,4,26,8,
 16,7,27,20,13,2,
 41,52,31,37,47,55,
 30,40,51,45,33,48,
 44,49,39,56,34,53,
 46,42,50,36,29,32
]

S_BOXES = [
 # S1
 [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
  [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
  [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
  [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
 # S2
 [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
  [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
  [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
  [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
 # S3
 [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
  [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
  [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
  [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
 # S4
 [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
  [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
  [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
  [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
 # S5
 [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
  [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
  [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
  [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
 # S6
 [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
  [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
  [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
  [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
 # S7
 [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
  [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
  [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
  [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
 # S8
 [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
  [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
  [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
  [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

LEFT_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# ----------------------
# HELPER BIT FUNCTIONS
# ----------------------

def permute(value: int, table: list, in_bits: int) -> int:
    out = 0
    for pos in table:
        bit = (value >> (in_bits - pos)) & 1
        out = (out << 1) | bit
    return out

def left_rotate(value: int, shift: int, width: int) -> int:
    mask = (1 << width) - 1
    return ((value << shift) & mask) | ((value & mask) >> (width - shift))

# ----------------------
# KEY SCHEDULE
# ----------------------

def generate_subkeys(key64: int):
    key56 = permute(key64, PC1, 64)  # 56-bit
    C = (key56 >> 28) & ((1 << 28) - 1)
    D = key56 & ((1 << 28) - 1)

    subkeys = []
    for shift in LEFT_SHIFTS:
        C = left_rotate(C, shift, 28)
        D = left_rotate(D, shift, 28)
        combined = (C << 28) | D   # 56-bit
        subkey48 = permute(combined, PC2, 56)
        subkeys.append(subkey48)
    return subkeys

# ----------------------
# FEISTEL (F) FUNCTION
# ----------------------

def feistel_f(R32: int, subkey48: int) -> int:
    expanded48 = permute(R32, E, 32)        # 48-bit
    xored = expanded48 ^ subkey48           # 48-bit

    out32 = 0
    for i in range(8):
        shift = 42 - 6 * i
        chunk = (xored >> shift) & 0x3F     # 6 bits
        row = ((chunk & 0x20) >> 4) | (chunk & 0x01)  # bits 1 & 6
        col = (chunk >> 1) & 0x0F
        s_val = S_BOXES[i][row][col]        # 4-bit
        out32 = (out32 << 4) | s_val

    p_out = permute(out32, P, 32)
    return p_out

# ----------------------
# BLOCK ENCRYPT/DECRYPT
# ----------------------

def des_block_crypt(block64: int, subkeys: list, decrypt=False) -> int:
    permuted = permute(block64, IP, 64)
    L = (permuted >> 32) & 0xFFFFFFFF
    R = permuted & 0xFFFFFFFF

    round_keys = list(reversed(subkeys)) if decrypt else subkeys

    for k in round_keys:
        temp = R
        R = L ^ feistel_f(R, k)
        L = temp

    preoutput = (R << 32) | L
    cipher = permute(preoutput, FP, 64)
    return cipher & 0xFFFFFFFFFFFFFFFF

# ----------------------
# PADDING / PROCESS BYTES
# ----------------------

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data or len(data) % block_size != 0:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]

def process_bytes(data: bytes, key64: int, decrypt=False) -> bytes:
    if not decrypt:
        data = pkcs7_pad(data, 8)
    out = bytearray()
    subkeys = generate_subkeys(key64)
    for i in range(0, len(data), 8):
        block = int.from_bytes(data[i:i+8], 'big')
        out_block = des_block_crypt(block, subkeys, decrypt=decrypt)
        out.extend(out_block.to_bytes(8, 'big'))
    if decrypt:
        out = pkcs7_unpad(bytes(out), 8)
    return bytes(out)

# ----------------------
# TEXT HELPERS
# ----------------------

def normalize_key_input(s: str) -> int:
    """
    Accept 16-hex chars or an ASCII key; convert to 64-bit int.
    (If ASCII shorter than 8 chars, it's NUL-padded; if longer, truncated.)
    """
    s = s.strip()
    hexchars = set(string.hexdigits)
    cleaned = s.replace(" ", "").replace("\n", "")
    if len(cleaned) == 16 and all(c in hexchars for c in cleaned):
        key_bytes = bytes.fromhex(cleaned)
    else:
        kb = s.encode('utf-8')
        if len(kb) < 8:
            kb = kb.ljust(8, b'\0')
        else:
            kb = kb[:8]
        key_bytes = kb
    return int.from_bytes(key_bytes, 'big')

def encrypt_text_to_hex(plaintext: str, key64: int) -> str:
    data = plaintext.encode('utf-8')  # preserves spaces/newlines
    cipher_bytes = process_bytes(data, key64, decrypt=False)
    return cipher_bytes.hex()

def decrypt_hex_to_text(hex_input: str, key64: int) -> str:
    cleaned = ''.join(hex_input.split())
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        data = hex_input.encode('utf-8')
    plain_bytes = process_bytes(data, key64, decrypt=True)
    try:
        return plain_bytes.decode('utf-8')
    except Exception:
        return plain_bytes.decode('utf-8', errors='replace')

# ----------------------
# KEY GENERATION (random with DES odd parity)
# ----------------------

def set_odd_parity_8bytes(b: bytes) -> bytes:
    """Return 8-byte sequence with DES odd parity enforced on each byte."""
    bb = bytearray(b)
    for i in range(8):
        x = bb[i] & 0xFE                 # clear parity bit (LSB)
        ones = bin(x).count("1")
        parity_bit = 0 if (ones % 2 == 1) else 1  # make total ones odd
        bb[i] = x | parity_bit
    return bytes(bb)

def generate_random_des_key_hex() -> str:
    k = secrets.token_bytes(8)           # 64-bit random
    k = set_odd_parity_8bytes(k)         # enforce DES odd parity
    return k.hex().upper()

# ----------------------
# TKINTER GUI
# ----------------------

class DESApp:
    def __init__(self, master):
        self.master = master
        master.title("DES (full) — Text mode (preserves spaces)")

        tk.Label(master, text="Key (hex 16 chars or ASCII):").grid(row=0, column=0, sticky='e')
        self.key_entry = tk.Entry(master, width=30)
        self.key_entry.grid(row=0, column=1, sticky='w')

        # Buttons to control key
        self.rand_btn = tk.Button(master, text="Random Key", command=self.fill_random_key)
        self.rand_btn.grid(row=0, column=2, padx=4)

        self.test_btn = tk.Button(master, text="Use Test Key", command=self.fill_test_key)
        self.test_btn.grid(row=0, column=3, padx=4)

        tk.Label(master, text="Rounds (fixed 16):").grid(row=1, column=0, sticky='e')
        self.rounds_label = tk.Label(master, text="16")
        self.rounds_label.grid(row=1, column=1, sticky='w')

        self.mode = tk.StringVar(value="encrypt")
        tk.Radiobutton(master, text="Encrypt", variable=self.mode, value="encrypt").grid(row=2, column=0)
        tk.Radiobutton(master, text="Decrypt", variable=self.mode, value="decrypt").grid(row=2, column=1)

        tk.Label(master, text="Input (plaintext OR ciphertext hex):").grid(row=3, column=0, columnspan=4, sticky='w')
        self.input_text = scrolledtext.ScrolledText(master, width=80, height=10)
        self.input_text.grid(row=4, column=0, columnspan=4, padx=4, pady=2)

        tk.Button(master, text="Run", command=self.run).grid(row=5, column=0, columnspan=2, pady=6)
        tk.Button(master, text="Clear", command=self.clear).grid(row=5, column=2, columnspan=2, pady=6)

        tk.Label(master, text="Output:").grid(row=6, column=0, columnspan=4, sticky='w')
        self.output_text = scrolledtext.ScrolledText(master, width=80, height=10)
        self.output_text.grid(row=7, column=0, columnspan=4, padx=4, pady=2)

        # Fill a fresh random key at startup
        self.fill_random_key()

    def fill_random_key(self):
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, generate_random_des_key_hex())

    def fill_test_key(self):
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, "133457799BBCDFF1")

    def run(self):
        key_text = self.key_entry.get()
        try:
            key64 = normalize_key_input(key_text)
        except Exception as e:
            messagebox.showerror("Key error", f"Invalid key: {e}")
            return

        mode = self.mode.get()
        inp = self.input_text.get("1.0", tk.END)  # DO NOT strip; preserve spaces/newlines
        if mode == "encrypt":
            out = encrypt_text_to_hex(inp, key64)
        else:
            out = decrypt_hex_to_text(inp, key64)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, out)

    def clear(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)

# ----------------------
# START GUI
# ----------------------
if __name__ == "__main__":
    print("Running DES self-test (standard test vector)...")
    root = tk.Tk()
    app = DESApp(root)
    root.mainloop()  