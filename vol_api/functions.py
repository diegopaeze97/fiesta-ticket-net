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


def get_debitoinmediato_code(payload):
    DEBIT_TARGET_URL = f"{_base_url}/cce/debit"
    """
    Construye y envía la petición de débito inmediato al endpoint /cce/debit del banco.
    Espera un JSON con al menos:
      - monto (number)
      - nombreBen (string)
      - cirifBen (string)  # identificación beneficiario
      - tipoPersonaBen (string)  # 'V'/'E' etc.
      - tipoDatoCuentaBen (string)  # 'CNTA' | 'CELE' | 'ALIS'
      - cuentaBen (string)  # instrumento (cuenta, teléfono, alias)
      - codBancoBen (string)  # codigo banco (ej '0134')
      - concepto (string)
    Opcional:
      - trackingId (string)
    Encripta dt con AES-CBC (función encrypt_aes_cbc) y envía { hs, dt }.
    Desencripta la respuesta (si viene en dt/response/data) y la retorna.
    """
    try:
        if not payload:
            return {"status_code": 400, "error": "payload vacío"}, 400

        # Validaciones mínimas
        monto = payload.get("monto", None)
        nombreBen = payload.get("nombreBen", None)
        cirifBen = payload.get("cirifBen", None)
        tipoPersonaBen = payload.get("tipoPersonaBen", None)
        tipoDatoCuentaBen = payload.get("tipoDatoCuentaBen", None)
        cuentaBen = payload.get("cuentaBen", None)
        codBancoBen = payload.get("codBancoBen", None)
        concepto = payload.get("concepto", None)
        trackingId = payload.get("trackingId", "1234")

        # Required checks
        if monto is None or monto == "":
            return {"status_code": 400, "error": "monto requerido"}, 400
        # Allow numeric types or numeric strings, convert to string representation with dot as decimal separator
        try:
            # keep same representation the caller sent if it's already a string with decimals,
            # else format float to string (avoid locale issues)
            if isinstance(monto, str):
                monto_str = monto
            else:
                monto_str = str(float(monto))
        except Exception:
            return {"status_code": 400, "error": "monto inválido"}, 400

        required_fields = {
            "nombreBen": nombreBen,
            "cirifBen": cirifBen,
            "tipoPersonaBen": tipoPersonaBen,
            "tipoDatoCuentaBen": tipoDatoCuentaBen,
            "cuentaBen": cuentaBen,
            "codBancoBen": codBancoBen,
            "concepto": concepto
        }
        missing = [k for k, v in required_fields.items() if not v]
        if missing:
            logging.error("Missing fields: %s", missing)
            return {"status_code": 400, "error": "faltan campos requeridos", "missing": missing}, 400

        # Optionally validate tipoDatoCuentaBen allowed values
        allowed_tipo = {"CNTA", "CELE", "ALIS"}
        if tipoDatoCuentaBen not in allowed_tipo:
            return {"status_code": 400, "error": "tipoDatoCuentaBen inválido", "allowed": list(allowed_tipo)}, 400

        dt_obj = {
            "monto": float(monto_str),  # bank sample shows numeric value (not string) — use numeric here
            "nombreBen": nombreBen,
            "cirifBen": cirifBen,
            "tipoPersonaBen": tipoPersonaBen,
            "tipoDatoCuentaBen": tipoDatoCuentaBen,
            "cuentaBen": cuentaBen,
            "codBancoBen": codBancoBen,
            "concepto": concepto,
            "token": "1",
            "indicador": "1",
            "trackingId": "123456" # prueba con trackingId fijo, ya que el banco lo requiere pero no especifica formato ni validación. En producción, se podría generar un UUID o similar para cada transacción.

        }
        #if trackingId:
        #    dt_obj["trackingId"] = trackingId

        print("DT object (debit): %s", dt_obj)

        logging.info("Construyendo DT débito inmediato para beneficiario: %s", nombreBen)

        dt_string = json.dumps(dt_obj, separators=(",", ":"), ensure_ascii=False)
        logging.debug("DT (debito) length=%d", len(dt_string))

        # Encriptar DT
        dt_encrypted_b64 = utils.encrypt_aes_cbc(dt_string)

        body = {
            "hs": BANK_HS,
            "dt": dt_encrypted_b64
        }

        logging.info("Enviando petición de débito inmediato a %s", DEBIT_TARGET_URL)
        headers = {"Content-Type": "application/json"}
        resp = requests.post(DEBIT_TARGET_URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        status_code = resp.status_code
        text = resp.text
        logging.info("Banco (debit) respondió status=%s body_len=%d", status_code, len(text))

        # Intentar parsear JSON
        try:
            resp_json = resp.json()
        except ValueError:
            resp_json = None

        decrypted = None
        if resp_json:
            enc_field = None
            if "response" in resp_json:
                enc_field = resp_json.get("response")
            elif "dt" in resp_json:
                enc_field = resp_json.get("dt")
            elif "data" in resp_json and isinstance(resp_json.get("data"), str):
                enc_field = resp_json.get("data")

            if enc_field:
                try:
                    decrypted_str = utils.decrypt_aes_cbc_from_b64(enc_field)
                    try:
                        decrypted = json.loads(decrypted_str)
                    except ValueError:
                        decrypted = {"raw_decrypted": decrypted_str}
                except Exception as e:
                    logging.exception("No se pudo desencriptar respuesta de débito: %s", e)
                    return {
                        "status_code": status_code,
                        "raw_response": resp_json,
                        "error": "fallo desencriptado"
                    }, 502
            else:
                # respuesta ya en claro
                return {"status_code": status_code, "response": resp_json}, status_code
        else:
            # No JSON: intentar desencriptar texto crudo
            try:
                decrypted_str = utils.decrypt_aes_cbc_from_b64(text.strip())
                try:
                    decrypted = json.loads(decrypted_str)
                except ValueError:
                    decrypted = {"raw_decrypted": decrypted_str}
            except Exception:
                return {"status_code": status_code, "raw_text": text}, status_code

        return {"status_code": status_code, "decrypted": decrypted}, status_code

    except requests.Timeout:
        logging.exception("Timeout al conectar con banco (debit)")
        return {"status_code": 504, "error": "timeout al conectar con el banco"}, 504
    except requests.exceptions.RequestException as e:
        logging.exception("Error de conexión con el banco (debit)")
        return {"status_code": 503, "error": "Error de conexión/red con el banco", "detail": str(e)}, 503
    except Exception as e:
        logging.exception("Error interno (debit): %s", e)
        return {"status_code": 500, "error": "error interno", "detail": str(e)}, 500


def validate_c2p_realtime(payment_data):
    C2P_TARGET_URL = f"{_base_url}/c2p"
    """
    Emisión de pago C2P (PagoMovil C2P).
    Espera JSON con al menos:
      - monto (string o number)
      - nacionalidad (string, ejemplo 'V')
      - cedula (string o number)
      - banco (codigo numérico de banco, e.g. '0104')
      - tlf | telefono (string con prefijo 58 + codigo area sin 0 + 7 digitos, e.g. 584125558877)
      - token (string)  # token del pagador para autorizar el pago
    Opcional:
      - email (string)
    El endpoint encripta dt y hace POST a /c2p del banco (envía { hs, dt }).
    Desencripta la respuesta y la devuelve al cliente.
    """
    try:
        if not BANK_HS:
            logging.error("BANK_HS no configurado, no se puede ejecutar C2P")
            return ({"error": "configuración de banco incompleta"}), 500

        # Aceptar distintas variantes de nombrado del teléfono y token
        monto = payment_data.get("monto") if "monto" in payment_data else payment_data.get("amount")
        nacionalidad = payment_data.get("nacionalidad") or payment_data.get("nacionality") or payment_data.get("nac")
        cedula = payment_data.get("cedula") or payment_data.get("ci") or payment_data.get("identificacion")
        banco = payment_data.get("banco") or payment_data.get("codBanco") or payment_data.get("bank")
        # tlf puede venir como 'tlf', 'telefono' o 'telefonoP' u otros
        tlf = payment_data.get("tlf") or payment_data.get("telefono") or payment_data.get("telefonoP") or payment_data.get("phone")
        token = payment_data.get("token") or payment_data.get("Token")
        email = payment_data.get("email") or payment_data.get("correo")

        # Validaciones básicas
        missing = []
        if monto is None or monto == "":
            missing.append("monto")
        if not nacionalidad:
            missing.append("nacionalidad")
        if not cedula:
            missing.append("cedula")
        if not banco:
            missing.append("banco")
        if not tlf:
            missing.append("tlf/telefono")
        if not token:
            missing.append("token")
        if missing:
            return ({"error": "faltan campos requeridos", "missing": missing}), 400

        # Normalizar monto: mantener string si viene como string, else formatear float con punto decimal
        try:
            if isinstance(monto, str):
                monto_str = monto
            else:
                # usar float para forzar formato con punto
                monto_str = str(float(monto))
        except Exception:
            return ({"error": "monto inválido"}), 400
        
        # Normalizar telefono: si empieza por 0, sustituimos por 58
        tlf_str = str(tlf).strip()
        if tlf_str.startswith("0"):
            tlf_str = "58" + tlf_str[1:]

        # Construir dt según especificación
        dt_obj = {
            "monto": monto_str,
            "nacionalidad": str(nacionalidad),
            "cedula": str(cedula),
            "banco": str(banco),
            "tlf": str(tlf_str),
            "token": str(token)
        }
        if email:
            dt_obj["email"] = str(email)

        logging.info("C2P: construyendo dt para cedula=%s banco=%s monto=%s", cedula, banco, monto_str)
        dt_string = json.dumps(dt_obj, separators=(",", ":"), ensure_ascii=False)

        # Encriptar DT
        dt_encrypted_b64 = utils.encrypt_aes_cbc(dt_string)

        body = {"hs": BANK_HS, "dt": dt_encrypted_b64}
        headers = {"Content-Type": "application/json"}

        logging.info("C2P: enviando petición a %s", C2P_TARGET_URL)
        resp = requests.post(C2P_TARGET_URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)

        status_code = resp.status_code
        text = resp.text
        logging.info("C2P: respuesta status=%s body_len=%d", status_code, len(text))

        # Intentar parsear JSON
        try:
            resp_json = resp.json()
        except ValueError:
            resp_json = None

        decrypted = None
        if resp_json:
            # campo encriptado puede ser 'response', 'dt' o 'data'
            enc_field = None
            if "response" in resp_json:
                enc_field = resp_json.get("response")
            elif "dt" in resp_json:
                enc_field = resp_json.get("dt")
            elif "data" in resp_json and isinstance(resp_json.get("data"), str):
                enc_field = resp_json.get("data")

            if enc_field:
                try:
                    decrypted_str = utils.decrypt_aes_cbc_from_b64(enc_field)
                    try:
                        decrypted = json.loads(decrypted_str)
                    except ValueError:
                        decrypted = {"raw_decrypted": decrypted_str}
                except Exception as e:
                    logging.exception("C2P: fallo desencriptado: %s", e)
                    return ({"status_code": status_code, "raw_response": resp_json, "error": "fallo desencriptado"}), 502
            else:
                # respuesta ya en claro
                return ({"status_code": status_code, "response": resp_json}), status_code
        else:
            # respuesta no JSON: intentar desencriptar texto crudo (posible b64)
            try:
                decrypted_str = utils.decrypt_aes_cbc_from_b64(text.strip())
                try:
                    decrypted = json.loads(decrypted_str)
                except ValueError:
                    decrypted = {"raw_decrypted": decrypted_str}
            except Exception:
                return ({"status_code": status_code, "raw_text": text}), status_code

        # Normalizar/retornar la respuesta desencriptada tal cual el banco la envíe
        return ({"status_code": status_code, "decrypted": decrypted}), status_code

    except requests.Timeout:
        logging.exception("C2P: timeout al conectar con banco")
        return ({"error": "timeout al conectar con el banco"}), 504
    except requests.exceptions.RequestException as e:
        logging.exception("C2P: error de conexión con el banco")
        return ({"error": "Error de conexión/red con el banco", "detail": str(e)}), 503
    except Exception as e:
        logging.exception("C2P: error interno: %s", e)
        return ({"error": "error interno", "detail": str(e)}), 500
    
