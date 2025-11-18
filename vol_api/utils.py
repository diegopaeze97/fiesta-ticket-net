import os
import base64
import logging
from datetime import datetime
from flask import Flask
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

# --- Config & logging ---
load_dotenv()
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

BANK_HS = os.getenv("BANK_HS", "")
BANK_KEY = os.getenv("BANK_KEY", "")
BANK_IV = os.getenv("BANK_IV", "")
BANK_TEST_URL = f'{os.getenv("BANK_TEST_URL", "https://200.135.106.250/rs")}/verifyP2C'
BANK_PROD_URL = os.getenv("BANK_PROD_URL", "https://cb.venezolano.com/rs/verifyP2C")
USE_PRODUCTION = os.getenv("USE_PRODUCTION", "false").lower() == "true"
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

if not (BANK_HS and BANK_KEY and BANK_IV):
    logging.warning("BANK_HS, BANK_KEY o BANK_IV no están configurados. Ver .env")

TARGET_URL = BANK_PROD_URL if USE_PRODUCTION else BANK_TEST_URL

# KEY/IV deben ser 16 bytes (AES-128)
def _to_bytes(value: str) -> bytes:
    # Si la env viene en base64, se podría decodificar; asumimos ASCII/utf-8 de 16 chars
    b = value.encode("utf-8")
    if len(b) not in (16, 24, 32):
        raise ValueError("La clave/IV debe tener longitud válida para AES (16/24/32 bytes).")
    return b

try:
    KEY = _to_bytes(BANK_KEY)
    IV = _to_bytes(BANK_IV)
except Exception as e:
    logging.error("Error con KEY/IV: %s", e)
    KEY = b"0"*16
    IV = b"0"*16

# --- Crypto helpers (AES CBC PKCS#7) ---
BLOCK_SIZE = 16

def encrypt_aes_cbc(plaintext: str) -> str:
    """
    Encrypt plaintext (UTF-8) using AES-128-CBC and return base64 encoded string.
    """
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(plaintext.encode("utf-8"), BLOCK_SIZE)  # PKCS#7
    ct = cipher.encrypt(padded)
    return base64.b64encode(ct).decode("utf-8")

def decrypt_aes_cbc_from_b64(b64_ciphertext: str) -> str:
    """
    Decode base64, decrypt AES-CBC and return decrypted UTF-8 string.
    """
    try:
        ct = base64.b64decode(b64_ciphertext)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        plain_padded = cipher.decrypt(ct)
        plain = unpad(plain_padded, BLOCK_SIZE).decode("utf-8")
        return plain
    except Exception as e:
        logging.exception("Error desencriptando: %s", e)
        raise

# --- Utilities ---
def normalize_referencia(ref: str) -> str:
    # tomar los últimos 12 dígitos si excede
    if not isinstance(ref, str):
        ref = str(ref)
    digits = ref.strip()
    # En el requerimiento: "tomar los últimos 12 dígitos en caso de tener más"
    return digits[-12:]

def validate_date_ddmmyyyy(date_str: str) -> bool:
    try:
        datetime.strptime(date_str, "%d/%m/%Y")
        return True
    except Exception:
        return False
