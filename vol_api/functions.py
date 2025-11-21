from flask import Blueprint
import vol_api.utils as utils
import json
import logging
import requests
import os

vol = Blueprint('vol', __name__)

BANK_HS = os.getenv("BANK_HS", "")
BANK_KEY = os.getenv("BANK_KEY", "")
BANK_IV = os.getenv("BANK_IV", "")
# Base URLs without endpoint - endpoint will be appended
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

def verify_p2c(payload):
    """
    Recibe JSON con keys: referencia, fecha (DD/MM/YYYY), banco, telefonoP, monto, processPayment (opcional), identificacion/pagador (opc)
    Build dt JSON, encripta y manda al banco; desencripta respuesta y la retorna.
    """
    try:
        
        if not payload:
            return {"error": "payload vacío"}, 400

        # Extracción y validaciones mínimas
        referencia = utils.normalize_referencia(payload.get("referencia", ""))
        fecha = payload.get("fecha", "")
        banco = payload.get("banco", "")
        telefonoP = payload.get("telefonoP", "")
        monto = payload.get("monto", "")
        processPayment = payload.get("processPayment", None)  # puede ser booleano o 1/0
        pagador = payload.get("pagador", None)
        identificacion = payload.get("identificacion", None)

        if not referencia:
            return {"error": "referencia requerida"}, 400
        if not utils.validate_date_ddmmyyyy(fecha):
            return {"error": "fecha inválida. Formato DD/MM/YYYY"}, 400
        if not banco:
            return {"error": "banco requerido"}, 400
        if not telefonoP:
            return {"error": "telefonoP requerido"}, 400
        if monto is None:
            return {"error": "monto requerido"}, 400

        # Construir dt según especificación - solo las keys esperadas
        dt_obj = {
            "referencia": referencia,
            "fecha": fecha,
            "banco": banco,
            "telefonoP": telefonoP,
            "monto": str(monto)  # banco puede esperar string con decimal
        }
        #if processPayment is not None:
            # Per bank documentation: send "1" to process, "0" to not process
          #  dt_obj["processPayment"] = format_process_payment(processPayment)
            #dt_obj["processPayment"] = True
        if pagador:
            dt_obj["pagador"] = pagador
        if identificacion:
            dt_obj["identificacion"] = identificacion

        dt_string = json.dumps(dt_obj, separators=(",", ":"), ensure_ascii=False)
        # Security: Do not log sensitive payment data (DT) in plaintext
        logging.info("DT (plaintext): %s", dt_string)

        # Encriptar DT
        dt_encrypted_b64 = utils.encrypt_aes_cbc(dt_string)

        # Construir body final
        body = {
            "hs": BANK_HS,
            "dt": dt_encrypted_b64
        }
        logging.info("Enviando petición a %s", TARGET_URL)
        logging.info("cuerpo de la solicitud encriptado: %s", body)

        # POST al banco
        headers = {"Content-Type": "application/json"}
        resp = requests.post(TARGET_URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)

        status_code = resp.status_code
        text = resp.text
        logging.info("Banco respondió status=%s body=%s", status_code, text[:1000])

        # Intentar parsear JSON
        try:
            resp_json = resp.json()
        except ValueError:
            # Respuesta no es JSON (posible error). Intentamos desencriptar si viene raw base64
            resp_json = None

        # 1) Si resp_json y tiene 'dt' o 'response' (encriptado), desencriptar
        decrypted = None
        if resp_json:
            # algunos endpoints devuelven {"response": "<b64>"}, otros {"dt":"<b64>"} u otros campos.
            enc_field = None
            if "response" in resp_json:
                enc_field = resp_json.get("response")
            elif "dt" in resp_json:
                enc_field = resp_json.get("dt")
            elif "data" in resp_json and isinstance(resp_json.get("data"), str):
                enc_field = resp_json.get("data")
            # else: tal vez ya esté en claro
            if enc_field:
                try:
                    decrypted_str = utils.decrypt_aes_cbc_from_b64(enc_field)
                    # parsed JSON dentro de dt
                    try:
                        decrypted = json.loads(decrypted_str)
                    except ValueError:
                        decrypted = {"raw_decrypted": decrypted_str}
                except Exception as e:
                    logging.exception("No se pudo desencriptar campo en respuesta: %s", e)
                    # devolvemos la respuesta cruda como fallback
                    return {
                        "status_code": status_code,
                        "raw_response": resp_json,
                        "error": "fallo desencriptado"
                    }, 502
            else:
                # si resp_json parece ya desencriptado (caso rare), retornarlo
                return {"status_code": status_code, "response": resp_json}, status_code

        else:
            # Resp no JSON: intentar desencriptar texto crudo (posible b64)
            try:
                decrypted_str = utils.decrypt_aes_cbc_from_b64(text.strip())
                try:
                    decrypted = json.loads(decrypted_str)
                except ValueError:
                    decrypted = {"raw_decrypted": decrypted_str}
            except Exception:
                # no pudimos parsear ni desencriptar: devolver texto crudo y código
                return {"status_code": status_code, "raw_text": text}, status_code
            
        logging.info("Respuesta desencriptada: %s", decrypted)

        # Si tenemos objeto desencriptado, devolverlo
        return {"status_code": status_code, "decrypted": decrypted}, status_code

    except requests.Timeout:
        logging.exception("Timeout al conectar con banco")
        return {"error": "timeout al conectar con el banco"}, 504
    except requests.exceptions.RequestException as e:
        # Atrapa otros errores de conexión (DNS, rechazo, etc.)
        logging.exception("Error de conexión con el banco")
        return {"error": "Error de conexión/red con el banco", "detail": str(e)}, 503
    except Exception as e:
        logging.exception("Error interno: %s", e)
        return {"error": "error interno", "detail": str(e)}, 500
