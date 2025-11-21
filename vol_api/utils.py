import os
import base64
import logging
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

# --- Config & logging ---
load_dotenv()
logging.basicConfig(level=logging.INFO)

BANK_HS = os.getenv("BANK_HS", "")
BANK_KEY = os.getenv("BANK_KEY", "")
BANK_IV = os.getenv("BANK_IV", "")
# Base URLs without endpoint - endpoint will be appended when needed
BANK_TEST_URL_BASE = os.getenv("BANK_TEST_URL", "https://200.135.106.250/rs")
BANK_PROD_URL_BASE = os.getenv("BANK_PROD_URL", "https://cb.venezolano.com/rs")
ENVIRONMENT = os.getenv("ENVIRONMENT").lower()
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

if not (BANK_HS and BANK_KEY and BANK_IV):
    logging.warning("BANK_HS, BANK_KEY o BANK_IV no están configurados. Ver .env")

# Construct TARGET_URL with endpoint
_base_url = BANK_PROD_URL_BASE if ENVIRONMENT in ['production', 'development'] else BANK_TEST_URL_BASE
# Avoid duplicating /verifyP2C if already present
if _base_url.endswith("/verifyP2C"):
    TARGET_URL = _base_url
else:
    TARGET_URL = f"{_base_url}/verifyP2C"

def parse_key_or_iv(value: str, param_name: str = "KEY/IV", expected_len: int = 16) -> bytes:
    """
    Parse and validate AES encryption key or IV.
    
    Accepts two formats:
    - Base64 encoded string (detected and decoded)
    - UTF-8 ASCII string
    
    Args:
        value: The key or IV string from environment variable
        param_name: Name of the parameter for error messages
        expected_len: Expected byte length (default 16 for AES-128)
    
    Returns:
        bytes: The validated key/IV as bytes
    
    Raises:
        ValueError: If value is empty, wrong length, or invalid format
    
    Note:
        This implementation enforces AES-128 (16 bytes) by default.
        No fallback to zero bytes is provided for security reasons.
    """
    if not value:
        raise ValueError(f"{param_name} no puede estar vacío. Configura la variable de entorno.")
    
    # Try Base64 decode first
    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) == expected_len:
            return decoded
        else:
            raise ValueError(
                f"{param_name} en Base64 debe decodificar a {expected_len} bytes, "
                f"pero tiene {len(decoded)} bytes."
            )
    except Exception:
        # Not valid Base64, try UTF-8 encoding
        pass
    
    # Try UTF-8 encoding
    try:
        encoded = value.encode("utf-8")
        if len(encoded) == expected_len:
            return encoded
        else:
            raise ValueError(
                f"{param_name} como texto UTF-8 debe ser exactamente {expected_len} bytes, "
                f"pero tiene {len(encoded)} bytes. "
                f"Usa Base64 o texto ASCII de {expected_len} caracteres."
            )
    except Exception as e:
        raise ValueError(f"Error al procesar {param_name}: {str(e)}")

# Parse and validate KEY and IV - fail fast if invalid (no fallback to zeros)
KEY = parse_key_or_iv(BANK_KEY, "BANK_KEY", 16)
IV = parse_key_or_iv(BANK_IV, "BANK_IV", 16)

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
    """
    Normalize bank reference by filtering non-digit characters and returning last 12 digits.
    
    Per bank documentation: Extract digits only and return the last 12 digits.
    
    Args:
        ref: Reference string (may contain letters, symbols, etc.)
    
    Returns:
        str: Last 12 digits, or fewer if less than 12 digits exist, or original last 12 chars if no digits
    
    Examples:
        '0123456789012345' -> '345678901234' (last 12 digits)
        'ABC123456789012345' -> '345678901234' (last 12 digits)
        'REF-1234567890' -> '234567890' (only 10 digits found)
        'ABCDEFGHIJKL' -> 'ABCDEFGHIJKL' (no digits, return last 12 chars)
    """
    if not isinstance(ref, str):
        ref = str(ref)
    
    # Filter only digits
    digits_only = ''.join(c for c in ref if c.isdigit())
    
    # If we have digits, return the last 12
    if digits_only:
        return digits_only[-12:]
    
    # If no digits, fallback to last 12 characters of original (edge case)
    return ref.strip()[-12:]

def format_process_payment(process_payment) -> str:
    """
    Convert processPayment value to bank-expected format ("1" or "0").
    
    Per bank documentation: Send "1" to process payment, "0" to not process.
    
    Args:
        process_payment: Can be bool, int, str ("1", "0", "true", "false", "True", "False")
    
    Returns:
        str: "1" to process, "0" to not process
    
    Examples:
        True -> "1"
        False -> "0"
        1 -> "1"
        0 -> "0"
        "true" -> "1"
        "false" -> "0"
    """
    if isinstance(process_payment, bool):
        return "1" if process_payment else "0"
    
    # Convert to string and normalize
    str_val = str(process_payment).lower().strip()
    
    if str_val in ("1", "true"):
        return "1"
    else:
        return "0"

def validate_date_ddmmyyyy(date_str: str) -> bool:
    try:
        datetime.strptime(date_str, "%d/%m/%Y")
        return True
    except Exception:
        return False

def format_amount(amount) -> str:
    """
    Format amount to string with 2 decimal places.
    
    Args:
        amount: Number or string representing amount
    
    Returns:
        str: Amount formatted as string with 2 decimals (e.g., "130.00")
    
    Examples:
        130 -> "130.00"
        130.5 -> "130.50"
        "130" -> "130.00"
    """
    try:
        # Convert to float and format with 2 decimals
        float_amount = float(amount)
        return f"{float_amount:.2f}"
    except (ValueError, TypeError):
        # If conversion fails, return as-is converted to string
        return str(amount)

def validate_phone_number(phone: str) -> bool:
    """
    Validate Venezuelan phone number format.
    
    Per bank documentation: Format should be 58 + area code (without leading 0) + 7-8 digits
    Example: 584241234567 (58 + 424 + 1234567)
    
    Args:
        phone: Phone number string
    
    Returns:
        bool: True if valid format, False otherwise
    """
    if not phone:
        return False
    
    # Remove any non-digit characters
    digits = ''.join(c for c in phone if c.isdigit())
    
    # Should start with 58 and have 12-13 digits total (58 + area code + 7-8 digits)
    if digits.startswith("58") and len(digits) in (12, 13):
        return True
    
    return False