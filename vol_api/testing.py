from flask import request, jsonify, Blueprint, current_app
import vol_api.utils as utils
import json
import logging
import requests
from vol_api.utils import (
    normalize_referencia, validate_date_ddmmyyyy, encrypt_aes_cbc, 
    decrypt_aes_cbc_from_b64, format_process_payment
)
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

# --- Endpoint público que tu app llamará ---
@vol.route("/verify-p2c", methods=["POST"])
def verify_p2c():
    TARGET_URL = f"{_base_url}/verifyP2C"
    """
    Recibe JSON con keys: referencia, fecha (DD/MM/YYYY), banco, telefonoP, monto, processPayment (opcional), identificacion/pagador (opc)
    Build dt JSON, encripta y manda al banco; desencripta respuesta y la retorna.
    """
    try:
        payload = request.get_json(force=True)
        if not payload:
            return jsonify({"error": "payload vacío"}), 400

        # Extracción y validaciones mínimas
        referencia = normalize_referencia(payload.get("referencia", ""))
        fecha = payload.get("fecha", "")
        banco = payload.get("banco", "")
        telefonoP = payload.get("telefonoP", "")
        monto = payload.get("monto", "")
        processPayment = payload.get("processPayment", None)  # puede ser booleano o 1/0
        pagador = payload.get("pagador", None)
        identificacion = payload.get("identificacion", None)

        if not referencia:
            return jsonify({"error": "referencia requerida"}), 400
        if not validate_date_ddmmyyyy(fecha):
            return jsonify({"error": "fecha inválida. Formato DD/MM/YYYY"}), 400
        if not banco:
            return jsonify({"error": "banco requerido"}), 400
        if not telefonoP:
            return jsonify({"error": "telefonoP requerido"}), 400
        if monto is None:
            return jsonify({"error": "monto requerido"}), 400

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

        print("DT (objeto):", dt_obj)

        dt_string = json.dumps(dt_obj, separators=(",", ":"), ensure_ascii=False)
        # Security: Do not log sensitive payment data (DT) in plaintext
        # logging.info("DT (plaintext): %s", dt_string)
        logging.info("Construyendo DT para referencia: %s", referencia)

        # Encriptar DT
        dt_encrypted_b64 = encrypt_aes_cbc(dt_string)

        print(BANK_HS)
        print(dt_string)

        # Construir body final
        body = {
            "hs": BANK_HS,
            "dt": dt_encrypted_b64
        }
        logging.info("Enviando petición a %s", TARGET_URL)

        print("BODY:", body)

        # POST al banco
        headers = {"Content-Type": "application/json"}
        resp = requests.post(TARGET_URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        print("RESP:", resp, resp.status_code, resp.text)
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
                    decrypted_str = decrypt_aes_cbc_from_b64(enc_field)
                    # parsed JSON dentro de dt
                    try:
                        decrypted = json.loads(decrypted_str)
                    except ValueError:
                        decrypted = {"raw_decrypted": decrypted_str}
                except Exception as e:
                    logging.exception("No se pudo desencriptar campo en respuesta: %s", e)
                    # devolvemos la respuesta cruda como fallback
                    return jsonify({
                        "status_code": status_code,
                        "raw_response": resp_json,
                        "error": "fallo desencriptado"
                    }), 502
            else:
                # si resp_json parece ya desencriptado (caso rare), retornarlo
                return jsonify({"status_code": status_code, "response": resp_json}), status_code

        else:
            # Resp no JSON: intentar desencriptar texto crudo (posible b64)
            try:
                decrypted_str = decrypt_aes_cbc_from_b64(text.strip())
                try:
                    decrypted = json.loads(decrypted_str)
                except ValueError:
                    decrypted = {"raw_decrypted": decrypted_str}
            except Exception:
                # no pudimos parsear ni desencriptar: devolver texto crudo y código
                return jsonify({"status_code": status_code, "raw_text": text}), status_code

        # Si tenemos objeto desencriptado, devolverlo
        return jsonify({"status_code": status_code, "decrypted": decrypted}), status_code

    except requests.Timeout:
        logging.exception("Timeout al conectar con banco")
        return jsonify({"error": "timeout al conectar con el banco"}), 504
    except requests.exceptions.RequestException as e:
        # Atrapa otros errores de conexión (DNS, rechazo, etc.)
        logging.exception("Error de conexión con el banco")
        return jsonify({"error": "Error de conexión/red con el banco", "detail": str(e)}), 503
    except Exception as e:
        logging.exception("Error interno: %s", e)
        return jsonify({"error": "error interno", "detail": str(e)}), 500

# --- Endpoint público para solicitar codigo de debito inmediato ---
# --- Endpoint público para solicitar codigo de debito inmediato ---
@vol.route("/get-debitoinmediato-code", methods=["POST"])
def get_debitoinmediato_code():
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
        payload = request.get_json(force=True)
        if not payload:
            return jsonify({"error": "payload vacío"}), 400

        # Validaciones mínimas
        monto = payload.get("monto", None)
        nombreBen = payload.get("nombreBen", None)
        cirifBen = payload.get("cirifBen", None)
        tipoPersonaBen = payload.get("tipoPersonaBen", None)
        tipoDatoCuentaBen = payload.get("tipoDatoCuentaBen", None)
        cuentaBen = payload.get("cuentaBen", None)
        codBancoBen = payload.get("codBancoBen", None)
        concepto = payload.get("concepto", None)
        trackingId = payload.get("trackingId", None)

        # Required checks
        if monto is None or monto == "":
            return jsonify({"error": "monto requerido"}), 400
        # Allow numeric types or numeric strings, convert to string representation with dot as decimal separator
        try:
            # keep same representation the caller sent if it's already a string with decimals,
            # else format float to string (avoid locale issues)
            if isinstance(monto, str):
                monto_str = monto
            else:
                monto_str = str(float(monto))
        except Exception:
            return jsonify({"error": "monto inválido"}), 400

        required_fields = {
            "nombreBen": nombreBen,
            "cirifBen": cirifBen,
            "tipoPersonaBen": tipoPersonaBen,
            "tipoDatoCuentaBen": tipoDatoCuentaBen,
            "cuentaBen": cuentaBen,
            "codBancoBen": codBancoBen,
            "concepto": concepto,
        }
        missing = [k for k, v in required_fields.items() if not v]
        if missing:
            return jsonify({"error": "faltan campos requeridos", "missing": missing}), 400

        # Optionally validate tipoDatoCuentaBen allowed values
        allowed_tipo = {"CNTA", "CELE", "ALIS"}
        if tipoDatoCuentaBen not in allowed_tipo:
            return jsonify({"error": "tipoDatoCuentaBen inválido", "allowed": list(allowed_tipo)}), 400

        dt_obj = {
            "monto": float(monto_str),  # bank sample shows numeric value (not string) — use numeric here
            "nombreBen": nombreBen,
            "cirifBen": cirifBen,
            "tipoPersonaBen": tipoPersonaBen,
            "tipoDatoCuentaBen": tipoDatoCuentaBen,
            "cuentaBen": cuentaBen,
            "codBancoBen": codBancoBen,
            "concepto": concepto
        }
        if trackingId:
            dt_obj["trackingId"] = trackingId

        logging.info("Construyendo DT débito inmediato para beneficiario: %s", nombreBen)

        dt_string = json.dumps(dt_obj, separators=(",", ":"), ensure_ascii=False)
        logging.debug("DT (debito) length=%d", len(dt_string))

        # Encriptar DT
        dt_encrypted_b64 = encrypt_aes_cbc(dt_string)

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
                    decrypted_str = decrypt_aes_cbc_from_b64(enc_field)
                    try:
                        decrypted = json.loads(decrypted_str)
                    except ValueError:
                        decrypted = {"raw_decrypted": decrypted_str}
                except Exception as e:
                    logging.exception("No se pudo desencriptar respuesta de débito: %s", e)
                    return jsonify({
                        "status_code": status_code,
                        "raw_response": resp_json,
                        "error": "fallo desencriptado"
                    }), 502
            else:
                # respuesta ya en claro
                return jsonify({"status_code": status_code, "response": resp_json}), status_code
        else:
            # No JSON: intentar desencriptar texto crudo
            try:
                decrypted_str = decrypt_aes_cbc_from_b64(text.strip())
                try:
                    decrypted = json.loads(decrypted_str)
                except ValueError:
                    decrypted = {"raw_decrypted": decrypted_str}
            except Exception:
                return jsonify({"status_code": status_code, "raw_text": text}), status_code

        return jsonify({"status_code": status_code, "decrypted": decrypted}), status_code

    except requests.Timeout:
        logging.exception("Timeout al conectar con banco (debit)")
        return jsonify({"error": "timeout al conectar con el banco"}), 504
    except requests.exceptions.RequestException as e:
        logging.exception("Error de conexión con el banco (debit)")
        return jsonify({"error": "Error de conexión/red con el banco", "detail": str(e)}), 503
    except Exception as e:
        logging.exception("Error interno (debit): %s", e)
        return jsonify({"error": "error interno", "detail": str(e)}), 500

@vol.route("/get-singulartx", methods=["POST"])
def getsingulartx():
    GETSINGULARTX_TARGET_URL = f"{_base_url}/getSingularTx"
    """
    Consulta por transacción (GETSINGULARTX).
    Espera JSON con:
      - fecha (DD/MM/YYYY) REQUIRED
      - referencia (opcional)
      - trackingId (opcional)
      - modalidad (opcional)  # 'DBI' o 'CTI' etc.
    Nota: al menos referencia o trackingId debe estar presente.
    Se encripta {fecha, referencia?, trackingId?, modalidad?} como dt y se envía al banco.
    Se intenta desencriptar la respuesta y devolverla.
    """
    try:
        if not BANK_HS:
            logging.error("BANK_HS no configurado, no se puede ejecutar GETSINGULARTX")
            return jsonify({"error": "configuración de banco incompleta"}), 500

        payload = request.get_json(force=True)
        if not payload:
            return jsonify({"error": "payload vacío"}), 400

        fecha = payload.get("fecha", "")
        referencia = payload.get("referencia", None)
        trackingId = payload.get("trackingId", None)
        modalidad = payload.get("modalidad", None)

        # Validaciones
        if not fecha or not validate_date_ddmmyyyy(fecha):
            return jsonify({"error": "fecha requerida en formato DD/MM/YYYY"}), 400

        if not referencia and not trackingId:
            return jsonify({"error": "se requiere referencia o trackingId (al menos uno)"}), 400

        dt_obj = {"fecha": fecha}
        if referencia:
            dt_obj["referencia"] = referencia
        if trackingId:
            dt_obj["trackingId"] = trackingId
        if modalidad:
            dt_obj["modalidad"] = modalidad

        logging.info("GETSINGULARTX: construyendo dt para fecha=%s referencia=%s trackingId=%s", fecha, bool(referencia), bool(trackingId))
        dt_string = json.dumps(dt_obj, separators=(",", ":"), ensure_ascii=False)

        dt_encrypted_b64 = encrypt_aes_cbc(dt_string)
        body = {"hs": BANK_HS, "dt": dt_encrypted_b64}
        headers = {"Content-Type": "application/json"}

        logging.info("GETSINGULARTX: enviando petición a %s", GETSINGULARTX_TARGET_URL)
        resp = requests.post(GETSINGULARTX_TARGET_URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)

        status_code = resp.status_code
        text = resp.text
        logging.info("GETSINGULARTX: respuesta status=%s body_len=%d", status_code, len(text))

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
                    decrypted_str = decrypt_aes_cbc_from_b64(enc_field)
                    try:
                        decrypted = json.loads(decrypted_str)
                    except ValueError:
                        decrypted = {"raw_decrypted": decrypted_str}
                except Exception as e:
                    logging.exception("GETSINGULARTX: fallo desencriptado: %s", e)
                    return jsonify({"status_code": status_code, "raw_response": resp_json, "error": "fallo desencriptado"}), 502
            else:
                # ya está en claro
                return jsonify({"status_code": status_code, "response": resp_json}), status_code
        else:
            # respuesta no JSON: intentar desencriptar texto crudo
            try:
                decrypted_str = decrypt_aes_cbc_from_b64(text.strip())
                try:
                    decrypted = json.loads(decrypted_str)
                except ValueError:
                    decrypted = {"raw_decrypted": decrypted_str}
            except Exception:
                return jsonify({"status_code": status_code, "raw_text": text}), status_code

        return jsonify({"status_code": status_code, "decrypted": decrypted}), status_code

    except requests.Timeout:
        logging.exception("GETSINGULARTX: timeout al conectar con banco")
        return jsonify({"error": "timeout al conectar con el banco"}), 504
    except requests.exceptions.RequestException as e:
        logging.exception("GETSINGULARTX: error de conexión con banco")
        return jsonify({"error": "Error de conexión/red con el banco", "detail": str(e)}), 503
    except Exception as e:
        logging.exception("GETSINGULARTX: error interno: %s", e)
        return jsonify({"error": "error interno", "detail": str(e)}), 500


@vol.route("/post-debitoinmediato-token", methods=["POST"])
def post_debitoinmediato_token():
    DEBIT_TOKEN_TARGET_URL = f"{_base_url}/cce/debit/token"
    """
    POST del token recibido por SMS para continuar el débito inmediato.
    Espera JSON con:
      - idPago (string o number) REQUIRED
      - token (string) REQUIRED
    Este endpoint envía { idPago, token } al endpoint /cce/debit/token del banco (encriptado).
    Nota: según la documentación, después de este POST es obligatorio ejecutar una consulta por transacción (GETSINGULARTX)
    para confirmar el estado final de la operación. Aquí devolvemos la respuesta del banco para que el cliente/proxy pueda,
    si corresponde, llamar /get-singulartx.
    """
    try:
        if not BANK_HS:
            logging.error("BANK_HS no configurado, no se puede ejecutar post_debitoinmediato_token")
            return jsonify({"error": "configuración de banco incompleta"}), 500

        payload = request.get_json(force=True)
        if not payload:
            return jsonify({"error": "payload vacío"}), 400

        idPago = payload.get("idPago", None)
        token = payload.get("token", None)

        if not idPago:
            return jsonify({"error": "idPago requerido"}), 400
        if not token:
            return jsonify({"error": "token requerido"}), 400

        dt_obj = {"idPago": str(idPago), "token": str(token)}
        dt_string = json.dumps(dt_obj, separators=(",", ":"), ensure_ascii=False)

        dt_encrypted_b64 = encrypt_aes_cbc(dt_string)
        body = {"hs": BANK_HS, "dt": dt_encrypted_b64}
        headers = {"Content-Type": "application/json"}

        logging.info("POST_DEBITO_TOKEN: enviando token a %s idPago=%s", DEBIT_TOKEN_TARGET_URL, idPago)
        resp = requests.post(DEBIT_TOKEN_TARGET_URL, json=body, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)

        status_code = resp.status_code
        text = resp.text
        logging.info("POST_DEBITO_TOKEN: respuesta status=%s body_len=%d", status_code, len(text))

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
                    decrypted_str = decrypt_aes_cbc_from_b64(enc_field)
                    try:
                        decrypted = json.loads(decrypted_str)
                    except ValueError:
                        decrypted = {"raw_decrypted": decrypted_str}
                except Exception as e:
                    logging.exception("POST_DEBITO_TOKEN: fallo desencriptado: %s", e)
                    return jsonify({"status_code": status_code, "raw_response": resp_json, "error": "fallo desencriptado"}), 502
            else:
                return jsonify({"status_code": status_code, "response": resp_json}), status_code
        else:
            # intentar desencriptar texto crudo
            try:
                decrypted_str = decrypt_aes_cbc_from_b64(text.strip())
                try:
                    decrypted = json.loads(decrypted_str)
                except ValueError:
                    decrypted = {"raw_decrypted": decrypted_str}
            except Exception:
                return jsonify({"status_code": status_code, "raw_text": text}), status_code

        # Informar al cliente que, por ser operación asíncrona, debe consultar estado con GETSINGULARTX
        return jsonify({
            "status_code": status_code,
            "decrypted": decrypted,
            "note": "Operación asíncrona: se recomienda ejecutar GETSINGULARTX (/get-singulartx) para consultar el estado final."
        }), status_code

    except requests.Timeout:
        logging.exception("POST_DEBITO_TOKEN: timeout al conectar con banco")
        return jsonify({"error": "timeout al conectar con el banco"}), 504
    except requests.exceptions.RequestException as e:
        logging.exception("POST_DEBITO_TOKEN: error de conexión con el banco")
        return jsonify({"error": "Error de conexión/red con el banco", "detail": str(e)}), 503
    except Exception as e:
        logging.exception("POST_DEBITO_TOKEN: error interno: %s", e)
        return jsonify({"error": "error interno", "detail": str(e)}), 500
    
@vol.route("/c2p", methods=["POST"])
def c2p_payment():
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
            return jsonify({"error": "configuración de banco incompleta"}), 500

        payload = request.get_json(force=True)
        if not payload:
            return jsonify({"error": "payload vacío"}), 400

        # Aceptar distintas variantes de nombrado del teléfono y token
        monto = payload.get("monto") if "monto" in payload else payload.get("amount")
        nacionalidad = payload.get("nacionalidad") or payload.get("nacionality") or payload.get("nac")
        cedula = payload.get("cedula") or payload.get("ci") or payload.get("identificacion")
        banco = payload.get("banco") or payload.get("codBanco") or payload.get("bank")
        # tlf puede venir como 'tlf', 'telefono' o 'telefonoP' u otros
        tlf = payload.get("tlf") or payload.get("telefono") or payload.get("telefonoP") or payload.get("phone")
        token = payload.get("token") or payload.get("Token")
        email = payload.get("email") or payload.get("correo")

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
            return jsonify({"error": "faltan campos requeridos", "missing": missing}), 400

        # Normalizar monto: mantener string si viene como string, else formatear float con punto decimal
        try:
            if isinstance(monto, str):
                monto_str = monto
            else:
                # usar float para forzar formato con punto
                monto_str = str(float(monto))
        except Exception:
            return jsonify({"error": "monto inválido"}), 400

        # Construir dt según especificación
        dt_obj = {
            "monto": monto_str,
            "nacionalidad": str(nacionalidad),
            "cedula": str(cedula),
            "banco": str(banco),
            "tlf": str(tlf),
            "token": str(token)
        }
        if email:
            dt_obj["email"] = str(email)

        logging.info("C2P: construyendo dt para cedula=%s banco=%s monto=%s", cedula, banco, monto_str)
        dt_string = json.dumps(dt_obj, separators=(",", ":"), ensure_ascii=False)

        # Encriptar DT
        dt_encrypted_b64 = encrypt_aes_cbc(dt_string)

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
                    decrypted_str = decrypt_aes_cbc_from_b64(enc_field)
                    try:
                        decrypted = json.loads(decrypted_str)
                    except ValueError:
                        decrypted = {"raw_decrypted": decrypted_str}
                except Exception as e:
                    logging.exception("C2P: fallo desencriptado: %s", e)
                    return jsonify({"status_code": status_code, "raw_response": resp_json, "error": "fallo desencriptado"}), 502
            else:
                # respuesta ya en claro
                return jsonify({"status_code": status_code, "response": resp_json}), status_code
        else:
            # respuesta no JSON: intentar desencriptar texto crudo (posible b64)
            try:
                decrypted_str = decrypt_aes_cbc_from_b64(text.strip())
                try:
                    decrypted = json.loads(decrypted_str)
                except ValueError:
                    decrypted = {"raw_decrypted": decrypted_str}
            except Exception:
                return jsonify({"status_code": status_code, "raw_text": text}), status_code

        # Normalizar/retornar la respuesta desencriptada tal cual el banco la envíe
        return jsonify({"status_code": status_code, "decrypted": decrypted}), status_code

    except requests.Timeout:
        logging.exception("C2P: timeout al conectar con banco")
        return jsonify({"error": "timeout al conectar con el banco"}), 504
    except requests.exceptions.RequestException as e:
        logging.exception("C2P: error de conexión con el banco")
        return jsonify({"error": "Error de conexión/red con el banco", "detail": str(e)}), 503
    except Exception as e:
        logging.exception("C2P: error interno: %s", e)
        return jsonify({"error": "error interno", "detail": str(e)}), 500