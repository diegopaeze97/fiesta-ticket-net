from flask import request, jsonify, Blueprint, current_app, g
from extensions import db, s3, stripe
from models import EventsUsers, Discounts, Event, Venue, Section, Seat, Ticket, BankReferences, Sales, Logs, Payments
from flask_jwt_extended import get_jwt
import logging
from sqlalchemy.orm import joinedload, load_only
from sqlalchemy import and_, or_, func, update
import os
import bleach
from datetime import datetime, timedelta, timezone
import eventos.utils as utils
import eventos.utils_whatsapp as WA_utils
from extensions import mail
from decorators.utils import optional_roles, roles_required
import requests
import re
import calendar
from dateutil import parser
import time
from models import Event
from requests.adapters import HTTPAdapter, Retry
import vol_api.functions as vol_utils
import qrcode

events = Blueprint('events', __name__)

# este modulo es la API que permite a terceros bloquear boleteria, emitirla, etc



events = Blueprint('events', __name__)

bancos_venezolanos = {
    "BANCO DE VENEZUELA": "0102",
    "BANCO VENEZOLANO DE CREDITO": "0104",
    "BANCO MERCANTIL": "0105",
    "BBVA PROVINCIAL": "0108",
    "BANCARIBE": "0114",
    "BANCO EXTERIOR": "0115",
    "BANCO CARONI": "0128",
    "BANESCO": "0134",
    "BANCO SOFITASA": "0137",
    "BANCO PLAZA": "0138",
    "BANGENTE": "0146",
    "BANCO FONDO COMUN": "0151",
    "100% BANCO": "0156",
    "DELSUR BANCO UNIVERSAL": "0157",
    "BANCO DEL TESORO": "0163",
    "BANCRECER": "0168",
    "R4 BANCO MICROFINANCIERO C.A.": "0169",
    "BANCO ACTIVO": "0171",
    "BANCAMIGA BANCO UNIVERSAL, C.A.": "0172",
    "BANCO INTERNACIONAL DE DESARROLLO": "0173",
    "BANPLUS": "0174",
    "BANCO DIGITAL DE LOS TRABAJADORES, BANCO UNIVERSAL": "0175",
    "BANFANB": "0177",
    "N58 BANCO DIGITAL BANCO MICROFINANCIERO S A": "0178",
    "BANCO NACIONAL DE CREDITO": "0191"
}


@events.route('/get-map', methods=['GET'])
def get_map():
    start_time = time.perf_counter()  # ⏱ Inicio total
    try:
        # ---------------------------------------------------------------
        # 1️⃣ Obtener parámetros y validaciones
        # ---------------------------------------------------------------
        event_id = request.args.get('query', '')
        tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
        tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

        if not all([event_id, tickera_id, tickera_api_key]):
            return jsonify({"message": "Faltan parámetros"}), 400

        # ---------------------------------------------------------------
        # 2️⃣ Buscar el evento en la base de datos
        # ---------------------------------------------------------------
        db_start = time.perf_counter()
        event = Event.query.options(
            load_only(
                Event.event_id,
                Event.event_id_provider,
                Event.name,
                Event.active,
                Event.SVGmap,
                Event.date_string,
                Event.hour_string
            ),
            joinedload(Event.venue).load_only(
                Venue.venue_id,
                Venue.name
            )
        ).filter_by(event_id=int(event_id)).one_or_none()

        db_end = time.perf_counter()

        if event is None or not event.active:
            logging.error("Evento no encontrado o inactivo")
            return jsonify({"message": "Evento no encontrado"}), 404

        # ---------------------------------------------------------------
        # 3️⃣ Hacer request externo (con retries, timeouts y envío seguro de credenciales)
        # ---------------------------------------------------------------

        url = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/load-map"
        query = str(event.event_id_provider).strip()  # normalizar / sanitizar

        # Construir sesión con reintentos para errores transitorios
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(['GET', 'POST'])
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Enviar credenciales en headers (evita que queden en logs/urls)
        headers = {
            "Accept": "application/json",
            "User-Agent": "FiestaTickets/1.0",
            "X-Tickera-Id": tickera_id,
            "X-Tickera-Api-Key": tickera_api_key
        }

        params = {"query": query}

        # Verificación de certificado configurable (True por defecto)
        verify = current_app.config.get("REQUESTS_VERIFY", True)

        req_start = time.perf_counter()
        try:
            # timeouts: (connect, read)
            response = session.get(url, params=params, headers=headers, timeout=(5, 60), allow_redirects=False, verify=verify)
            req_end = time.perf_counter()

            # Validaciones básicas de seguridad / integridad
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                logging.error("Respuesta inesperada de Tickera: Content-Type no es JSON")
                response.raise_for_status()

        except requests.exceptions.RequestException:
            req_end = time.perf_counter()
            logging.exception("Error al comunicarse con Tickera")
            # Re-lanzar para que el handler exterior lo capture y responda apropiadamente
            raise
        finally:
            try:
                session.close()
            except Exception:
                pass

        # ---------------------------------------------------------------
        # 4️⃣ Procesar respuesta
        # ---------------------------------------------------------------
        process_start = time.perf_counter()
        if response.status_code == 200:
            tickets_list = []
            tickets = response.json().get("tickets", [])

            now = datetime.now(timezone.utc)  # Siempre en UTC

            for t in tickets:
                status = t.get("status", "desconocido")
                if status not in ["disponible", "en carrito"]:
                    status = "bloqueado"
                # convertir expires_at a timestamp para comparar con now
                expires_raw = t.get("expires_at")

                expires_dt = None
                expires_ts = None
                if isinstance(expires_raw, (int, float)):
                    expires_ts = float(expires_raw)
                elif isinstance(expires_raw, str):
                    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                        try:
                            expires_dt = datetime.strptime(expires_raw, fmt)
                            expires_ts = calendar.timegm(expires_dt.utctimetuple())
                            break
                        except Exception:
                            continue

                now_ts = calendar.timegm(now.utctimetuple())

                # Comparación segura
                if status == "en carrito":
                    if expires_raw is None or expires_ts <= now_ts:
                        status = "disponible"
                    else:
                        status = "en carrito"
                elif status == "disponible":
                    status = "disponible"
                    
                tickets_list.append({
                    "ticket_id": t["ticket_id"],
                    "status": status,
                    "row": t["row"],
                    "number": t["number"],
                    "section": t["section"],
                    "price": t["price"],
                    "svg_id": t["svg_id"],
                    "expires_at": t["expires_at"],
                })
            process_end = time.perf_counter()
            
            total_end = time.perf_counter()
            print(f"⏱ Tiempos (segundos):")
            print(f"  - DB lookup: {db_end - db_start:.4f}")
            print(f"  - Request externo: {req_end - req_start:.4f}")
            print(f"  - Procesamiento respuesta: {process_end - process_start:.4f}")
            print(f"  - Total: {total_end - start_time:.4f}")

            event_details  = {  
                "event_id": event.event_id,
                "name": event.name,
                "date": event.date_string,
                "hour": event.hour_string,
                "place": event.venue.name if event.venue else None,
                "description": event.description if hasattr(event, 'description') else None,
                "duration": event.duration if hasattr(event, 'duration') else None,
                "clasification": event.clasification if hasattr(event, 'clasification') else None,
                "age_restriction": event.age_restriction if hasattr(event, 'age_restriction') else None,
                "mainImage": event.mainImage if hasattr(event, 'mainImage') else None,
            }

            return jsonify(
                tickets=tickets_list,
                venue_map=event.SVGmap,
                event=event_details,
                status="ok",
                timing={
                    "db_lookup": round(db_end - db_start, 4),
                    "external_request": round(req_end - req_start, 4),
                    "processing": round(process_end - process_start, 4),
                    "total": round(total_end - start_time, 4)
                }
            ), 200
        else:
            process_end = time.perf_counter()
            total_end = time.perf_counter()
            logging.error(f"⏱ Request externo fallido en {req_end - req_start:.4f} segundos")

            return jsonify({
                "status": "error",
                "code": response.status_code,
                "message": response.json().get("message", "Error desconocido"),
                "timing": {
                    "db_lookup": round(db_end - db_start, 4),
                    "external_request": round(req_end - req_start, 4),
                    "processing": round(process_end - process_start, 4),
                    "total": round(total_end - start_time, 4)
                }
            }), response.status_code

    except requests.exceptions.RequestException as e:
        total_end = time.perf_counter()
        logging.error(f"❌ Error en request tras {total_end - start_time:.4f} segundos")
        return jsonify({"message": f"Error en el request: {str(e)}"}), 500

    

@events.route('/get-events', methods=['GET'])
def get_events():
    try:
        events = Event.query.options(joinedload(Event.venue)).filter(Event.active == True).all()

        if events is None or len(events) == 0:
            return jsonify({"message": "No se encontraron eventos", "status": "error"}), 404

        events_list = []
        for event in events:
            event_data = {
                "event_id": event.event_id,
                "name": event.name,
                "Description": event.description,
                "date": event.date_string,
                "hour": event.hour_string,
                "Venue": {
                    "VenueID": event.venue.venue_id,
                    "name": event.venue.name,
                    "address": event.venue.address,
                    "city": event.venue.city,
                } if event.venue else None,
                "mainImage": event.mainImage,
                "bannerImage": event.bannerImage,
                "bannerImageDevice": event.bannerImageDevice
            }
            events_list.append(event_data)

        return jsonify({"events": events_list, "status": "ok"}), 200
    except Exception as e:
        logging.error(f"Error al obtener eventos: {str(e)}")
        return jsonify({"message": "Error al obtener eventos", "status": "error"}), 500
    
@events.route('/buy-tickets', methods=['POST'])
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def buy_tickets():
    try:
        # ---------------------------------------------------------------
        # 1️⃣ Parámetros desde el frontend
        # ---------------------------------------------------------------
        data = request.get_json(silent=True) or {}
        user_id = get_jwt().get("id")

        event_id = request.args.get('query', '')
        selected_seats = data.get('tickets', [])
        discount_code = data.get('discount_code', '').strip()

        tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
        tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

        if not all([event_id, selected_seats, user_id, tickera_id, tickera_api_key]):
            return jsonify({"message": "Faltan parámetros obligatorios"}), 400
        
        if len(selected_seats) > 6:
            return jsonify({"message": "No se pueden comprar más de 6 boletos a la vez"}), 400

        # ---------------------------------------------------------------
        # 2️⃣ Validar evento
        # ---------------------------------------------------------------
        event = Event.query.filter_by(event_id=int(event_id)).first()
        if not event or not event.active:
            return jsonify({"message": "Evento no encontrado o inactivo"}), 404

        # ---------------------------------------------------------------
        # 3️⃣ Validar cliente
        # ---------------------------------------------------------------
        customer = EventsUsers.query.filter(EventsUsers.CustomerID == int(user_id)).one_or_none()
        if not customer:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        if customer.status.lower() != "verified":
            return jsonify({'message': 'La cuenta no ha sido verificada.'}), 403
        
        # ---------------------------------------------------------------
        #
        #

        if discount_code:
            discount_code = bleach.clean(discount_code.upper(), strip=True)
            validated_discount = utils.validate_discount_code(discount_code, customer, event, selected_seats, 'buy')
            if not validated_discount["status"]:
                return jsonify({"message": validated_discount["message"]}), 400
        
        # ---------------------------------------------------------------
        # 7️⃣ Llamar a la API para calcular la tasa en bolivares BCV
        # ---------------------------------------------------------------
        get_bs_exchange_rate = utils.get_exchange_rate_bsd()
        # Validar respuesta y extraer la tasa de cambio de forma robusta
        raw_rate = None
        message = None
        if isinstance(get_bs_exchange_rate, dict):
            raw_rate = get_bs_exchange_rate.get('exchangeRate')
            message = get_bs_exchange_rate.get('message')
        # Rechazar si no hay tasa o la tasa es cero (no válida)
        if raw_rate is None or raw_rate == 0:
            db.session.rollback()
            return jsonify({'message': message or 'error desconocido al intentar obtener la tasa de cambio', 'status': 'error'}), 500
        try:
            BsDexchangeRate = int(raw_rate)
        except Exception:
            db.session.rollback()
            return jsonify({'message': 'Tasa de cambio en formato inválido', 'status': 'error'}), 500


        customer.BsDExchangeRate = int(BsDexchangeRate)
        # ---------------------------------------------------------------
        # 4️⃣ Validar tickets disponibles en sistema
        # ---------------------------------------------------------------
        now = datetime.now(timezone.utc)  # Siempre en UTC



        ticket_ids = [int(s['ticket_id']) for s in selected_seats]

        # Traer también desde la API de mapa para validar estado
        # ---------------------------------------------------------------
        # 3️⃣ Hacer request externo (con retries, timeouts y envío seguro de credenciales)
        # ---------------------------------------------------------------

        url = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/load-map"
        query = str(event.event_id_provider).strip()  # normalizar / sanitizar

        # Construir sesión con reintentos para errores transitorios
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(['GET', 'POST'])
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Enviar credenciales en headers (evita que queden en logs/urls)
        headers = {
            "Accept": "application/json",
            "User-Agent": "FiestaTickets/1.0",
            "X-Tickera-Id": tickera_id,
            "X-Tickera-Api-Key": tickera_api_key
        }

        params = {"query": query}

        # Verificación de certificado configurable (True por defecto)
        verify = current_app.config.get("REQUESTS_VERIFY", True)

        try:
            # timeouts: (connect, read)
            response = session.get(url, params=params, headers=headers, timeout=(5, 60), allow_redirects=False, verify=verify)

            # Validaciones básicas de seguridad / integridad
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                logging.error("Respuesta inesperada de Tickera: Content-Type no es JSON")
                response.raise_for_status()

        except requests.exceptions.RequestException:
            logging.exception("Error al comunicarse con Tickera")
            # Re-lanzar para que el handler exterior lo capture y responda apropiadamente
            raise
        finally:
            try:
                session.close()
            except Exception:
                pass

        # ---------------------------------------------------------------
        # 5️⃣ Manejo de errores desde Tickera
        # ---------------------------------------------------------------

        tickets_api = response.json().get("tickets", [])
        ticket_map = {int(t['ticket_id']): t for t in tickets_api if t.get('status') in ['disponible', 'en carrito']}

        # Validar que todos los tickets existan y estén disponibles
        for s in selected_seats:
            tid = int(s['ticket_id'])
            tdata = ticket_map.get(tid)
            if not tdata:
                return jsonify({
                    "status": "error",
                    "message": f"El asiento {s['row']}{s['number']} de la sección {s['section']} no está disponible"
                }), 400

            # Normalizar expires_at a timestamp para evitar errores con datetimes naive/aware
            expires_raw = tdata.get('expires_at')
            expires_dt_utc = None
                
            if expires_raw:
                try:
                    # 1. Parsear la cadena (maneja ISO y muchos otros formatos, y offsets)
                    expires_dt_generic = parser.parse(expires_raw)
                    
                    # 2. Convertir a AWARE en UTC para la comparación
                    if expires_dt_generic.tzinfo is None:
                        # Si es naive, asumimos que Tickera la manda en UTC
                        expires_dt_utc = expires_dt_generic.replace(tzinfo=timezone.utc)
                    else:
                        # Si es aware (ya tiene offset), lo convertimos a UTC
                        expires_dt_utc = expires_dt_generic.astimezone(timezone.utc)
                        
                except Exception as e:
                    # Manejo de error si el formato es irreconocible
                    logging.error(f"Error al parsear fecha de expiración: {expires_raw} -> {e}")
                    expires_dt_utc = None # Tratar como no expirado para no bloquear
                    
            # Realiza la comparación con los objetos datetime aware
            if (
                tdata['status'] == 'en carrito' and
                expires_dt_utc is not None and
                expires_dt_utc > now # <-- Ambos son AWARE en UTC
            ):
                return jsonify({
                    "status": "error",
                    "message": f"El asiento {s['row']}{s['number']} de la sección {s['section']} está reservado"
                }), 400

        # ---------------------------------------------------------------
        # 6️⃣ Liberar tickets antiguos del cliente
        # ---------------------------------------------------------------
        old_tickets_db = Ticket.query.filter(and_(
            Ticket.event_id == int(event.event_id),
            Ticket.customer_id == int(customer.CustomerID),
            Ticket.status == 'en carrito'
        )).all()

        old_ticket_ids = [t.ticket_id_provider for t in old_tickets_db]

        # ---------------------------------------------------------------
        # 7️⃣ Llamar a la API de Tickera para bloquear tickets
        # ---------------------------------------------------------------
        """
        Envía petición POST a /eventos_api/reserve-tickets de forma segura:
        - Credenciales en headers (no en el body)
        - Retries/timeouts/verify
        - Sanitización básica de payload
        - Validación de Content-Type y manejo seguro de la respuesta
        """

        # URL
        url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/reserve-tickets"

        # Normalizar valores
        event_id = str(event.event_id_provider).strip()
        # Limitar tamaño y caracteres aceptables (ajusta según necesidad)
        if not event_id or len(event_id) > 64 or not event_id.isdigit():
            raise ValueError("event_id inválido")

        # Sanitizar tickets: lista de enteros, sin duplicados, límite razonable
        def clean_ticket_list(lst):
            if not lst:
                return []
            out = []
            for x in lst:
                try:
                    xi = int(x)
                except Exception:
                    continue
                out.append(xi)
            # dedup y límite (p. ej. 200)
            out = list(dict.fromkeys(out))
            if len(out) > 200:
                raise ValueError("Demasiados tickets en la petición")
            return out

        tickets_to_block = clean_ticket_list(ticket_ids)
        old_tickets = clean_ticket_list(old_ticket_ids)

        # expire_at (ISO, UTC 'Z') — asegurar formato y rango (<= 24h por ejemplo)
        now = datetime.now(timezone.utc)
        expire_dt_aware = now + timedelta(minutes=10)
        expire_at_str = expire_dt_aware.replace(microsecond=0).isoformat() + "Z"

        payload = {
            "event": event_id,
            "tickets": tickets_to_block,
            "expire_at": expire_at_str,
            "old_tickets": old_tickets,
        }

        # Session con retries
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(['GET', 'POST'])
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "FiestaTickets/1.0",
            "X-Tickera-Id": str(tickera_id),
            "X-Tickera-Api-Key": str(tickera_api_key)
        }

        verify = current_app.config.get("REQUESTS_VERIFY", True)

        try:
            response = session.post(
                url_block,
                json=payload,
                headers=headers,
                timeout=(5, 60),      # connect, read
                allow_redirects=False,
                verify=verify
            )

            # Seguridad: validar content-type JSON
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                logging.error("Respuesta inesperada de Tickera: Content-Type no es JSON")
                response.raise_for_status()

            # Levantar excepción for non-2xx
            response.raise_for_status()

            # Parsear JSON de forma segura
            try:
                data = response.json()
            except ValueError:
                logging.error("Respuesta JSON inválida de Tickera")
                raise

            # Guardar la respuesta para continuar con el flujo local sin salir prematuramente
            reserve_response = data

        except requests.exceptions.RequestException:
            logging.exception("Error al comunicarse con Tickera (reserve-tickets)")
            raise
        finally:
            try:
                session.close()
            except Exception:
                pass
            
        # 2️⃣ Liberar tickets anteriores del cliente
        db.session.query(Ticket).filter(and_(
            Ticket.event_id == event.event_id,
            Ticket.customer_id == customer.CustomerID,
            Ticket.status == 'en carrito'
        )).update({
            Ticket.status: 'disponible',
            Ticket.customer_id: None,
            Ticket.fee: 0,
            Ticket.discount: 0,
            Ticket.expires_at: None
        }, synchronize_session=False)

        db.session.commit()  # asegura limpieza antes de nueva asignación

        # 3️⃣ Cargar tickets actualizados del sistema
        tickets_sistema = Ticket.query.filter(and_(
            Ticket.event_id == event.event_id,
            or_(Ticket.status == 'disponible', Ticket.status == 'en carrito')
        )).all()

        amount_total = 0

        # 4️⃣ Asignar nuevos tickets
        for ticket_sistema in tickets_sistema:
            if not ticket_sistema.ticket_id_provider:
                continue

            for s in selected_seats:
                if int(ticket_sistema.ticket_id_provider) == int(s['ticket_id']):
                    ticket_sistema.status = 'en carrito'
                    ticket_sistema.customer_id = customer.CustomerID
                    ticket_sistema.fee = (event.Fee * ticket_sistema.price / 100) if event.Fee else 0
                    ticket_sistema.expires_at = expire_dt_aware

                    amount_total += ticket_sistema.price

        amount_total = int(round(amount_total/100, 2))

        # ---------------------------------------------------------------
        # 9️⃣ Confirmar cambios en BD local
        # ---------------------------------------------------------------
        db.session.commit()
        utils.sendnotification_for_CartAdding(current_app.config, db, mail, customer, selected_seats, event)
        return jsonify({
            "message": "Tickets bloqueados exitosamente",
            "status": "ok",
            "tickets": selected_seats,
            "total": amount_total
        }), 200

    except requests.exceptions.RequestException as e:
        db.session.rollback()
        return jsonify({"message": f"Error de conexión con Tickera: {str(e)}"}), 500

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error en /buy-tickets: {e}", exc_info=True)
        return jsonify({"message": "Error interno al procesar la compra"}), 500

    finally:
        db.session.close()

@events.route('/get-paymentdetails', methods=['GET'])
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def get_paymentdetails():
    user_id = get_jwt().get("id")
    event_id = request.args.get('query', '')
    discount_code = request.args.get('discount_code', '').strip()

    if not event_id:
        return jsonify({"message": "Falta el ID de evento"}), 400

    if not event_id.isdigit():
        return jsonify({"message": "ID de evento inválido"}), 400

    if not all([user_id]):
        return jsonify({"message": "Faltan parámetros obligatorios"}), 400
    
    try:

        # ---------------------------------------------------------------
        # 3️⃣ Validar cliente
        # ---------------------------------------------------------------
        customer = EventsUsers.query.filter(EventsUsers.CustomerID == int(user_id)).one_or_none()
        if not customer:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        
        if customer.status.lower() == "suspended":
            return jsonify({'message': 'Su cuenta se encuentra suspendida. Pongase en contacto con el administrador del sitio para mas detalles'}), 403  
        if customer.status.lower() != "verified":
            return jsonify({'message': 'La cuenta no ha sido verificada.'}), 403  
        
        tickets_en_carrito = Ticket.query.options(
            load_only(Ticket.ticket_id, Ticket.price, Ticket.expires_at),
            joinedload(Ticket.seat)
            .load_only(Seat.row, Seat.number)
            .joinedload(Seat.section)
            .load_only(Section.name),
            joinedload(Ticket.event)
            .load_only(Event.Fee, Event.name, Event.date_string, Event.hour_string)
            .joinedload(Event.venue)
            .load_only(Venue.venue_id, Venue.name)
        ).filter(
            Ticket.customer_id == int(customer.CustomerID),
            Ticket.status == 'en carrito',
            Ticket.event_id == int(event_id)
        ).limit(6).all()

        if not tickets_en_carrito or len(tickets_en_carrito) == 0:
            return jsonify({"message": "No hay tickets en el carrito", "status": "error"}), 404
        
        tickets = []
        total_price = 0
        total_fee = 0
        total_discount = 0
        expires_at = None

        event_details = tickets_en_carrito[0].event
        Fee = event_details.Fee if event_details.Fee else 0
        
        if discount_code:
            discount_code = bleach.clean(discount_code.upper(), strip=True)
            validated_discount = utils.validate_discount_code(discount_code, customer, event_details, tickets_en_carrito, 'buy')
            if not validated_discount["status"]:
                return jsonify({"message": validated_discount["message"]}), 400
            else:
                total_discount = validated_discount['total_discount']
        
        for ticket in tickets_en_carrito:
            seat = ticket.seat
            section = seat.section if seat else None

            section_name = (section.name.lower().replace(' ', '') if section else "sinseccion")
            row_name = seat.row if seat and seat.row else "sinfila"
            number = (seat.number if seat and seat.number else "sinnumero")

            tickets.append({
                "ticket_id": ticket.ticket_id,
                "price": ticket.price,
                "section": section_name,
                "row": row_name,
                "number": number
            })
            total_price += ticket.price
            if not expires_at or (ticket.expires_at and ticket.expires_at < expires_at):
                expires_at = ticket.expires_at

            total_fee += (Fee * ticket.price / 100) if Fee else 0

            if ticket.expires_at < datetime.utcnow():
                return jsonify({"message": "Tu reserva ha caducado", "status": "error"}), 400
            
        number_json = None
            
        if customer.PhoneNumber:
            customer_phone = customer.PhoneNumber 
            customer_phone = customer_phone.replace("+", "").replace(" ", "").replace("-", "")
            # Busca: 1–3 dígitos país, 3 dígitos prefijo, 7 dígitos número
            m = re.match(r'^(\d{1,3})(\d{10})$', customer_phone)
            if m:
                sufix = m.group(1)
                fullnumber = m.group(2)
                number_json = {
                    "country_code": sufix,
                    "number": fullnumber
                }
            else:
                number_json = None

        event_dict  = {  
            "name": event_details.name,
            "date": event_details.date_string,
            "hour": event_details.hour_string,
            "place": event_details.venue.name if event_details.venue else None
        }


        return jsonify({
            "tickets": tickets,
            "event": event_dict,
            "total_price": total_price,
            "total_discount": total_discount,
            "total_fee": total_fee,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "BsDExchangeRate": customer.BsDExchangeRate,
            "customer_phone": number_json,
            "status": "ok"
        }), 200
    except Exception as e:
        logging.error(f"Error al obtener detalles de pago: {str(e)}")
        db.session.rollback()
        return jsonify({"message": "Error al obtener detalles de pago", "status": "error"}), 500
    finally:
        db.session.close()

@events.route('/block-tickets', methods=['POST'])
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def block_tickets():
    user_id = get_jwt().get("id")
    data = request.get_json()
    event_id = request.args.get('query', '')
    discount_code = request.args.get('discount_code', '')

    payment_method = data.get("paymentMethod")
    payment_reference = data.get("paymentReference")
    phone_number = data.get("pagomovilPhoneNumber")
    contact_phone = data.get("contactPhoneNumber")
    contact_phone_prefix = data.get("countryCode")
    bank = data.get("bank")
    

    tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
    tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

    # ----------------------------------------------------------------
    # 1️⃣ Validaciones iniciales
    # ----------------------------------------------------------------
    if not all([user_id, payment_method, tickera_id, tickera_api_key, event_id]):
        return jsonify({"message": "Faltan parámetros obligatorios"}), 400

    if payment_method not in ["pagomovil", "efectivo", "zelle"]:
        return jsonify({"message": "Método de pago no válido"}), 400

    # ----------------------------------------------------------------
    # 2️⃣ Validar información del pago
    # ----------------------------------------------------------------
    full_phone_number = None
    if payment_method == "pagomovil":
        if not all([bank, payment_reference, phone_number]):
            return jsonify({"message": "Complete todos los campos requeridos"}), 400

        if not utils.venezuelan_phone_pattern.match(phone_number):
            return jsonify({"message": "Número de teléfono no válido"}), 400
        
        lista_de_bancos_venezolanos = [banco for banco in bancos_venezolanos.keys()]

        if bank.upper() not in lista_de_bancos_venezolanos:
            return jsonify({"message": "Banco no válido"}), 400
        
        bank_code = bancos_venezolanos.get(bank.upper())

        payment_status = "pagado por verificar"

        reference_clean = bleach.clean(payment_reference, strip=True)
        reference_no_zeros = reference_clean.lstrip("0")
        match_reference = BankReferences.query.filter_by(reference=reference_no_zeros).first()

        if match_reference:
            return jsonify({"message": "La referencia de pago ya ha sido utilizada, comunícate con nosotros para mayor información."}), 400

    else:
        if not all([contact_phone, contact_phone_prefix]):
            return jsonify({"message": "Complete todos los campos requeridos"}), 400

        full_phone_number = f"{contact_phone_prefix}{contact_phone}".replace("+", "").replace(" ", "").replace("-", "")
        if not utils.phone_pattern.match(full_phone_number):
            return jsonify({"message": "Número de teléfono no válido"}), 400

        payment_status = "pendiente pago"

    # ----------------------------------------------------------------
    # 3️⃣ Validar cliente
    # ----------------------------------------------------------------
    customer = EventsUsers.query.filter_by(CustomerID=int(user_id)).one_or_none()
    if not customer:
        return jsonify({"message": "Usuario no encontrado"}), 404

    if customer.status.lower() == "suspended":
        return jsonify({"message": "Su cuenta está suspendida."}), 403

    if customer.status.lower() != "verified":
        return jsonify({"message": "Su cuenta no está verificada."}), 403

    # ----------------------------------------------------------------
    # 4️⃣ Obtener tickets en carrito
    # ----------------------------------------------------------------
    # Validar que event_id sea numérico antes de convertirlo a int
    if not str(event_id).isdigit():
        return jsonify({"message": "ID de evento inválido"}), 400

    tickets_en_carrito = Ticket.query.options(
        joinedload(Ticket.seat).joinedload(Seat.section),
        joinedload(Ticket.event)
    ).filter(
        Ticket.customer_id == int(customer.CustomerID),
        Ticket.status == 'en carrito',
        Ticket.event_id == int(event_id)
    ).all()

    if not tickets_en_carrito:
        return jsonify({"message": "No hay tickets en el carrito"}), 404


    if len(tickets_en_carrito) > 6:
        return jsonify({"message": "No se pueden comprar más de 6 boletos a la vez"}), 400

    event = tickets_en_carrito[0].event
    if not event or not event.active:
        return jsonify({"message": "Evento no encontrado o inactivo"}), 404

    now = datetime.now(timezone.utc)  # Siempre en UTC
    for t in tickets_en_carrito:
        # 1. Convierte t.expires_at a aware ASUMIENDO que es UTC
        if t.expires_at and t.expires_at.tzinfo is None:
            expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at_aware = t.expires_at # Ya tiene info de zona horaria
        if not expires_at_aware or expires_at_aware < now:
            return jsonify({"message": "Tu reserva ha caducado"}), 400

    # ----------------------------------------------------------------
    # 5️⃣ Bloquear en Tickera (antes de modificar BD local)
    # ----------------------------------------------------------------
    url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/block-tickets"

    # Normalizar event id
    event_id = str(event.event_id_provider).strip()
    if not event_id or not event_id.isdigit() or len(event_id) > 64:
        raise ValueError("event_id inválido")
    
    # Sanitizar tickets_en_carrito
    def clean_tickets(list_in):
        out = []
        if not list_in:
            return out
        for i, t in enumerate(list_in):
            tid = t.ticket_id_provider
            price = t.price
            try:
                tid_i = int(tid)
            except Exception:
                continue
            # Price -> Decimal, >= 0
            out.append({"ticket_id_provider": tid_i, "price": str(price), "discount": 0})
            if len(out) >= 200:
                break
        return out
    
    tickets_payload = clean_tickets(tickets_en_carrito)
    total_discount = 0
    discount_id = None

    if discount_code:
        discount_code = bleach.clean(discount_code.upper(), strip=True)
        validated_discount = utils.validate_discount_code(discount_code, customer, event, tickets_en_carrito, 'block')
        if not validated_discount["status"]:
            return jsonify({"message": "Código de descuento inválido"}), 400
        total_discount = validated_discount['total_discount']
        tickets_payload = validated_discount['tickets']
        discount_id = validated_discount['discount_id']


    if not tickets_payload:
        raise ValueError("No hay tickets válidos para bloquear")

    payload = {
        "event": event_id,
        "tickets": tickets_payload,
        "type_of_sale": "user_sale"
    }

    # Session con retries
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "FiestaTickets/1.0",
        "X-Tickera-Id": str(tickera_id),
        "X-Tickera-Api-Key": str(tickera_api_key)
    }

    verify = current_app.config.get("REQUESTS_VERIFY", True)
    # Initialize holder so later local DB logic can run using this response if needed
    try:
        response = session.post(
            url_block,
            json=payload,
            headers=headers,
            timeout=(5, 30),
            allow_redirects=False,
            verify=verify
        )

        content_type = response.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            logging.error("Respuesta inesperada de Tickera en block-tickets: Content-Type no es JSON")
            response.raise_for_status()

        # Levantar para status >= 400
        response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            logging.error("JSON inválido en respuesta de block-tickets")
            raise

        # store the response instead of returning early so local changes can be applied
        block_response = data

    except requests.exceptions.RequestException:
        logging.exception("Error comunicándose con Tickera (block-tickets)")
        raise
    finally:
        try:
            session.close()
        except Exception:
            pass

    # ----------------------------------------------------------------
    # 6️⃣ Aplicar cambios locales (una sola transacción)
    # ----------------------------------------------------------------
    try:
        total_price = sum(t.price for t in tickets_en_carrito)
        total_fee = sum(round((event.Fee or 0) * t.price / 100, 2) for t in tickets_en_carrito)
        ticket_str_ids = '|'.join(str(t.ticket_id) for t in tickets_en_carrito)

        # Crear registro de venta
        sale = Sales(
            ticket_ids=ticket_str_ids,
            price=total_price,
            paid=0,
            user_id=user_id,
            status=payment_status,
            created_by=user_id,
            StatusFinanciamiento='decontado',
            event=event.event_id,
            fee=total_fee,
            discount=total_discount,
            ContactPhoneNumber=full_phone_number,
            discount_ref=discount_id
        )
        db.session.add(sale)
        db.session.flush()

        # Actualizar tickets
        for t in tickets_en_carrito:
            t.status = payment_status
            t.sale_id = sale.sale_id
            t.expires_at = None

        today = datetime.utcnow().date()
        MontoBS = int((total_price + total_fee - total_discount) * customer.BsDExchangeRate / 100)

        payment = Payments(
            SaleID=sale.sale_id,
            Amount=total_price + total_fee - total_discount,
            PaymentDate=today,
            PaymentMethod=payment_method,
            Reference=payment_reference,
            Status='pendiente',
            CreatedBy=user_id,
            MontoBS=MontoBS,
            Bank=bank,
            PhoneNumber=phone_number
        )
        db.session.add(payment)

        # ----------------------------------------------------------------
        # 7️⃣ Enviar notificación según método de pago
        # ----------------------------------------------------------------
        serializer = current_app.config['serializer']
        token = serializer.dumps({'user_id': user_id, 'sale_id': sale.sale_id})
        qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={token}'
        localizador = os.urandom(3).hex().upper()

        sale.saleLink = token
        sale.saleLocator = localizador

        total_abono = round((total_price + total_fee - total_discount) / 100, 2)

        sale_data = {
            'sale_id': sale.sale_id,
            'event': sale.event_rel.name,
            'venue': sale.event_rel.venue.name,
            'date': sale.event_rel.date_string,
            'hour': sale.event_rel.hour_string,
            'price': round(sale.price / 100, 2),
            'discount': round(sale.discount / 100, 2),
            'fee': round(sale.fee / 100, 2),
            'total_abono': total_abono,
            'payment_method': payment_method.capitalize(),
            'payment_date': today.strftime('%d-%m-%Y'),
            'reference': payment_reference or 'N/A',
            'link_reserva': qr_link,
            'localizador': localizador,
        }

        USE_PRODUCTION = current_app.config.get('USE_PRODUCTION', 'false') == "true"

        if payment_method == "pagomovil":
            sale_data.update({
                'status': 'pagado',
                'title': 'Estamos procesando tu abono',
                'subtitle': 'Te notificaremos una vez que haya sido aprobado',
                'due': round(0, 2),
            })

            payment_data = {}
            payment_data['fecha'] = today.strftime('%d/%m/%Y') if USE_PRODUCTION else '07/11/2025'
            payment_data['banco'] = bank_code
            payment_data['telefonoP'] = phone_number
            payment_data['referencia'] = payment_reference
            payment_data['monto'] = float(round(MontoBS/100000, 2)) if USE_PRODUCTION else 15.0
            
            try:
                response= vol_utils.verify_p2c(payment_data)
                data = response[0]

                if data['status_code'] == 200:
                    payment.Status = 'pagado'
                    sale.status = 'pagado'
                    sale.StatusFinanciamiento = 'pagado'

                    notify_customer = bvc_api_verification_success(current_app.config, tickets_en_carrito, payment, customer, discount_code)

                    if notify_customer['status'] == 'error':
                        logging.error(f"Error enviando notificación al cliente: {notify_customer['message']}")
                    
                    bank_obtained_ref = str(data['decrypted'].get('referencia')) if data.get('decrypted') else None
                    bank_obtained_ref_no_zeros = bank_obtained_ref.lstrip("0") if bank_obtained_ref else None

                    new_reference = BankReferences(
                        reference=bank_obtained_ref_no_zeros,
                    )
                    db.session.add(new_reference)
                    db.session.commit()
                    
                    return jsonify({"message": "Pago verificado y registrado exitosamente", "status": "ok", "tickets": notify_customer['tickets'], "total": total_abono}), 200
                else:
                    logging.info(f"PagoMóvil no verificado: {data.get('message', 'sin mensaje')}")
                    
                    
            except Exception as e:
                logging.error(f"Error verificando pago por PagoMóvil: {str(e)}")

        sale_data.update({
            'status': 'pendiente',
            'title': 'Hemos recibido tu solicitud de pago',
            'subtitle': 'Un miembro de nuestro equipo te contactará para confirmar los detalles',
            'due': round((total_price + total_fee - total_discount) / 100, 2),
        })

        if total_discount > 0:
            if discount_code:
                discount = Discounts.query.filter(Discounts.Code == discount_code).first()
                if discount:
                    discount.UsedCount = (discount.UsedCount or 0) + 1

        # Confirmar todo
        db.session.commit()

        tickets = []

        for ticket in tickets_en_carrito:

            seat = ticket.seat
            section = seat.section if seat else None

            section_name = (section.name.lower().replace(' ', '') if section else "sinseccion")
            row_name = seat.row if seat and seat.row else "sinfila"
            number = (seat.number if seat and seat.number else "sinnumero")

            tickets.append({
                "ticket_id": ticket.ticket_id,
                "price": round(ticket.price/100, 2),
                "section": section_name,
                "row": row_name,
                "number": number
            })

        # ---------------------------------------------------------------
        # Enviar notificación por email al cliente
        # ---------------------------------------------------------------

        utils.sendnotification_for_Blockage(current_app.config, db, mail, customer, tickets, sale_data)

        # ---------------------------------------------------------------
        # Notificar a administración sobre nueva venta/pago por whatsapp
        # ---------------------------------------------------------------
        WA_utils.send_new_sale_notification(current_app.config, customer, tickets, sale_data, full_phone_number)
        # ---------------------------------------------------------------

        return jsonify({"message": "Tickets bloqueados y venta registrada exitosamente", "status": "pending", "tickets": tickets, "total": total_abono}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error registrando venta o pago: {str(e)}")
        return jsonify({"message": "Error al registrar la venta o pago", "status": "error"}), 500
    finally:
        db.session.close()


@events.route('/reservation', methods=['GET']) 
def reservation():
    reservation_id = request.args.get('query', '')
    try:
        if reservation_id:
            sale = Sales.query.filter(
                and_(
                    Sales.saleLink == reservation_id,
                )
            ).one_or_none()

            if not sale:
                return jsonify({'message': 'Reserva no encontrada', 'status': 'ok', 'reservation_status': 'missing'}), 200

            if sale.status == 'cancelado':
                return jsonify({'message': 'Reserva cancelada', 'status': 'ok', 'reservation_status': 'broken'}), 200

            return jsonify({'message': 'Reserva existente', 'status': 'ok'}), 200

        else:
            return jsonify({'message': 'Reserva no encontrada', 'status': 'ok', 'reservation_status': 'missing'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar reserva: {e}")
        return jsonify({'message': 'Error al buscar reserva', 'status': 'error'}), 500
    
@events.route('/view-reservation', methods=['POST']) 
def view_reservation():
    input1 = request.json.get('input1')
    input2 = request.json.get('input2')
    input3 = request.json.get('input3')
    input4 = request.json.get('input4')
    input5 = request.json.get('input5')
    input6 = request.json.get('input6')
    reservation_id = request.json.get('reservation_id')

    if not all([input1, input2, input3, input4, input5, input6, reservation_id]):
        return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

    locator = (input1 + input2 + input3 + input4 + input5 + input6).upper().strip()

    try:
        if reservation_id:
            sale = Sales.query.filter(
                and_(
                    Sales.saleLink == reservation_id,
                    Sales.saleLocator == locator
                )
            ).one_or_none()

            if not sale:
                logging.info('no sale')
                return jsonify({'message': 'Reserva no encontrada', 'status': 'ok', 'reservation_status': 'missing'}), 400

            if sale.status == 'cancelado':
                return jsonify({'message': 'Reserva cancelada, por favor contacta a un administrador', 'status': 'ok', 'reservation_status': 'broken'}), 400
            
            payments_list = []
            payments = Payments.query.filter(Payments.SaleID == sale.sale_id).all()
            if payments:
                for entry in payments:
                    payments_list.append({
                        'amount': round(int(entry.Amount)/100, 2),
                        'date': entry.PaymentDate,
                        'paymentMethod': entry.PaymentMethod,
                        'paymentReference': entry.Reference,
                        'paymentVerified': entry.Status
                    })

            information = {}

            event_name = sale.event_rel.name if sale.event else ''
            venue_name = sale.event_rel.venue.name if sale.event and sale.event_rel.venue else ''
            event_date = sale.event_rel.date_string if sale.event else ''
            event_hour = sale.event_rel.hour_string if sale.event else ''
            

            due_dates = []
            if sale.due_dates:
                due_dates_entries = sale.due_dates.split('||') if '||' in sale.due_dates else [sale.due_dates]
                for entry in due_dates_entries:
                    due_date, amount, paid = entry.split('|', 1)
                    due_dates.append({
                        'due_date': due_date,
                        'amount': round(int(amount)/100, 2),
                        'paid': paid == 'True'
                    })

            tickets = []
            ticket_ids = sale.ticket_ids.split('|') if '|' in sale.ticket_ids else [sale.ticket_ids]
            for ticket_id in ticket_ids:
                if ticket_id:
                    ticket = Ticket.query.get(int(ticket_id))
                    if ticket:
                        seat = Seat.query.get(ticket.seat_id)
                        section = Section.query.get(seat.section_id) if seat else None
                        tickets.append({
                            'ticket_id': ticket.ticket_id,
                            'price': round(ticket.price/100, 2),
                            'status': ticket.status,
                            'section': section.name if section else None,
                            'row': seat.row if seat else None,
                            'number': seat.number if seat else None
                        })

            discount = round(sale.discount/100, 2) if sale.discount else 0
            fee = round(sale.fee/100, 2) if sale.fee else 0

            information['due_dates'] = [due_dates]
            information['payments'] = payments_list
            information['items'] = tickets
            information['total_price'] = round((sale.price  + sale.fee - sale.discount)/100, 2)
            information['paid'] = round(sale.paid/100, 2)
            information['due'] = round((sale.price + sale.fee - sale.discount - sale.paid)/100, 2)
            information['status'] = sale.status
            information['event'] = event_name
            information['venue'] = venue_name
            information['date'] = event_date
            information['hour'] = event_hour
            information['locator'] = sale.saleLocator
            information['StatusFinanciamiento'] = sale.StatusFinanciamiento 
            information['Email'] = sale.customer.Email if sale.customer else ''
            information['Fullname'] = sale.customer.FirstName + ' ' + sale.customer.LastName if sale.customer else ''
            information['fee'] = fee
            information['discount'] = discount
            information['subtotal'] = round(sale.price/100, 2)

            return jsonify({'message': 'Reserva existente', 'status': 'ok', 'information': information}), 200

        else:
            return jsonify({'message': 'Reserva no encontrada', 'status': 'error'}), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar reserva: {e}")
        return jsonify({'message': 'Error al buscar reserva', 'status': 'error'}), 500
    
@events.route('/ticket', methods=['GET'])
@optional_roles('admin', 'tiquetero')
def ticket():
    reservation_id = request.args.get('query', '')
    try:
        if reservation_id:
            ticket = Ticket.query.filter(
                Ticket.saleLink == reservation_id
            ).one_or_none()

            if not ticket:
                return jsonify({'message': 'Ticket invalido', 'status': 'ok', 'ticket_status': 'missing'}), 200

            if ticket.status == 'cancelado':
                return jsonify({'message': 'Ticket cancelado', 'status': 'ok', 'ticket_status': 'broken'}), 200

            # 👇 lógica compartida
            base_response = {
                'message': 'Ticket existente',
                'status': 'ok',
                'ticket_status': 'valid'
            }

            fee = ticket.fee if ticket.fee else 0 
            discount = round(ticket.discount, 2) if ticket.discount else 0

            # si tiene rol permitido, añade info adicional
            if g.has_access:
                base_response['information'] = {
                    'row': ticket.seat.row,
                    'number': ticket.seat.number,
                    'section': ticket.seat.section.name,   
                    'price': round(ticket.price/100, 2),
                    'fee': round(fee)/100,
                    'discount': round(discount)/100,
                    'total': round((ticket.price + fee - discount)/100, 2),
                    'status': ticket.status,
                    'event': ticket.event.name if ticket.event_id else '',
                    'venue': ticket.event.venue.name if ticket.event_id and ticket.event.venue else '',
                    'date': ticket.event.date_string if ticket.event_id else '',
                    'hour': ticket.event.hour_string if ticket.event_id else '',
                    'locator': ticket.saleLocator,
                    'availability_status': ticket.availability_status,
                    'ticketID': ticket.ticket_id,
                    'canjeoDate': ticket.canjeo_date
                }

            return jsonify(base_response), 200

        else:
            return jsonify({'message': 'Ticket invalido', 'status': 'ok', 'ticket_status': 'missing'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar ticket: {e}")
        return jsonify({'message': 'Error del servidor', 'status': 'error'}), 400

    
@events.route('/view-ticket', methods=['POST']) 
def view_ticket():
    input1 = request.json.get('input1')
    input2 = request.json.get('input2')
    input3 = request.json.get('input3')
    input4 = request.json.get('input4')
    input5 = request.json.get('input5')
    input6 = request.json.get('input6')
    reservation_id = request.json.get('reservation_id')

    if not all([input1, input2, input3, input4, input5, input6, reservation_id]):
        return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

    locator = (input1 + input2 + input3 + input4 + input5 + input6).upper().strip()

    try:
        if reservation_id:
            ticket = Ticket.query.filter(
                and_(
                    Ticket.saleLink == reservation_id,
                    Ticket.saleLocator == locator
                )
            ).one_or_none()

            if not ticket:
                logging.info('no sale')
                return jsonify({'message': 'ticket no encontrado', 'status': 'ok', 'reservation_status': 'missing'}), 400

            if ticket.status == 'cancelado':
                return jsonify({'message': 'Ticket anulado, por favor contacta a un administrador', 'status': 'ok', 'reservation_status': 'broken'}), 400

            information = {}

            event_name = ticket.event.name if ticket.event_id else ''
            venue_name = ticket.event.venue.name if ticket.event_id and ticket.event.venue else ''
            event_date = ticket.event.date_string if ticket.event_id else ''
            event_hour = ticket.event.hour_string if ticket.event_id else ''

            fee = ticket.fee if ticket.fee else 0
            discount = round(ticket.discount/100, 2) if ticket.discount else 0

            information['ticketID'] = ticket.ticket_id
            information['row'] = ticket.seat.row
            information['number'] = ticket.seat.number
            information['section'] = ticket.seat.section.name
            information['price'] = round(ticket.price/100, 2)
            information['fee'] = round(fee)/100
            information['discount'] = round(discount)/100
            information['total'] = round((ticket.price + fee - discount)/100, 2)
            information['status'] = ticket.status
            information['availability_status'] = ticket.availability_status
            information['event'] = event_name
            information['venue'] = venue_name
            information['date'] = event_date
            information['hour'] = event_hour
            information['locator'] = ticket.saleLocator
            information['canjeoDate'] = ticket.canjeo_date

            return jsonify({'message': 'Reserva existente', 'status': 'ok', 'information': information}), 200

        else:
            return jsonify({'message': 'Reserva no encontrada', 'status': 'error'}), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar reserva: {e}")
        return jsonify({'message': 'Error al buscar reserva', 'status': 'error'}), 500
    
@events.route('/canjear-ticket', methods=['GET'])  #canjeo de tickets
@roles_required(allowed_roles=["admin", "tiquetero"])
def canjear_ticket():
    ticket_id = request.args.get('query', '')
    try:
        now = datetime.now(timezone.utc)
        if ticket_id:
            ticket = Ticket.query.filter(
                and_(
                    Ticket.ticket_id == int(ticket_id),
                )
            ).one_or_none()

            if not ticket:
                return jsonify({'message': 'Ticket no encontrado', 'status': 'error', 'ticket_status': 'missing'}), 400

            if ticket.availability_status == 'cancelado':
                return jsonify({'message': 'Ticket cancelado, por favor contacta a un administrador', 'status': 'error', 'ticket_status': 'broken'}), 400

            if ticket.availability_status == 'Canjeado':
                return jsonify({'message': 'Este Ticket ya fue canjeado', 'status': 'ok', 'ticket_status': 'used'}), 400

            ticket.availability_status = 'Canjeado'
            ticket.canjeo_date = now
            db.session.commit()

            return jsonify({'message': 'Ticket canjeado exitosamente', 'status': 'ok', 'ticket_status': 'used'}), 200

        else:
            return jsonify({'message': 'Ticket no encontrado', 'status': 'ok', 'ticket_status': 'missing'}), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar ticket: {e}")
        return jsonify({'message': 'Error al buscar ticket', 'status': 'error'}), 500


@events.route("/create-stripe-checkout-session", methods=["GET"])
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def create_stripe_checkout_session():
    user_id = get_jwt().get("id")
    event_id = request.args.get('query', '')
    discount_code = request.args.get('discount_code', '')

    # ----------------------------------------------------------------
    # 1️⃣ Validaciones iniciales
    # ----------------------------------------------------------------
    if not all([user_id, event_id]):
        return jsonify({"message": "Faltan parámetros obligatorios"}), 400
    
    try:

        # ----------------------------------------------------------------
        # 3️⃣ Validar cliente
        # ----------------------------------------------------------------
        customer = EventsUsers.query.filter_by(CustomerID=int(user_id)).one_or_none()
        if not customer:
            return jsonify({"message": "Usuario no encontrado"}), 404

        if customer.status.lower() == "suspended":
            return jsonify({"message": "Su cuenta está suspendida."}), 403

        if customer.status.lower() != "verified":
            return jsonify({"message": "Su cuenta no está verificada."}), 403

        # ----------------------------------------------------------------
        # 4️⃣ Obtener tickets en carrito
        # ----------------------------------------------------------------
        # Validate event_id is numeric and convert to int
        if not str(event_id).isdigit():
            return jsonify({"message": "ID de evento inválido"}), 400
        event_id_int = int(event_id)

        tickets_en_carrito = Ticket.query.options(
            joinedload(Ticket.seat).joinedload(Seat.section),
            joinedload(Ticket.event)
        ).filter(
            Ticket.customer_id == customer.CustomerID,
            Ticket.status == 'en carrito',
            Ticket.event_id == event_id_int
        ).all()

        if not tickets_en_carrito:
            return jsonify({"message": "No hay tickets en el carrito"}), 404


        if len(tickets_en_carrito) > 6:
            return jsonify({"message": "No se pueden comprar más de 6 boletos a la vez"}), 400

        event = tickets_en_carrito[0].event

        if not event or not event.active:
            return jsonify({"message": "Evento no encontrado o inactivo"}), 404
        
        total_discount = 0
        ### validamos el descuento
        if discount_code:
            discount_validation = utils.validate_discount_code(discount_code, customer, event, tickets_en_carrito, 'buy')
            if not discount_validation.get('status'):
                return jsonify({"message": discount_validation.get('message', 'Error en el descuento')}), 400
            else:
                total_discount = discount_validation.get('total_discount', 0)
        
        tickets_list = []
        tickets_ids = ""
        total_to_pay = 0

        now = datetime.now(timezone.utc)  # Siempre en UTC
        for t in tickets_en_carrito:
            # 1. Convierte t.expires_at a aware ASUMIENDO que es UTC
            if t.expires_at and t.expires_at.tzinfo is None:
                expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
            else:
                expires_at_aware = t.expires_at # Ya tiene info de zona horaria
            if not expires_at_aware or expires_at_aware < now:
                return jsonify({"message": "Tu reserva ha caducado"}), 400
            
            seat = t.seat
            section = seat.section if seat else None

            section_name = (section.name.lower().replace(' ', '') if section else "sinseccion")
            row_name = seat.row if seat and seat.row else "sinfila"
            number = (seat.number if seat and seat.number else "sinnumero")

            tickets_ids += f"{t.ticket_id}|"

            total_to_pay += t.price

            tickets_list.append({
                "section": section_name,
                "price": t.price,
                "seat": f"{row_name}{number}",
            })

        total_fee = (event.Fee or 0) * total_to_pay / 100
        total_fee_int = int(total_fee)

        tickets_ids = tickets_ids[:-1]  # Elimina el último "|"

        if total_discount > (total_to_pay + total_fee):
            total_discount = total_to_pay + total_fee

        # ----------------------------------------------------------------
        # 4️⃣ Crear cupón de descuento en Stripe
        # ----------------------------------------------------------------
        stripe_coupon_id = None
        if total_discount > 0:
            coupon = stripe.Coupon.create(
                amount_off=int(round(total_discount, 2)),
                currency="usd"
            )
            stripe_coupon_id = coupon.id

        # ----------------------------------------------------------------
        # 5️⃣ Crear line_items para Stripe
        # ----------------------------------------------------------------

        # Usa la lista de diccionarios 'tickets_list' que ya contiene la info formateada
        line_items = [
            {
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": f"Asiento {t['section']} - {t['seat']} - {event.name}"},
                    # Asegúrate que 't['price']' es el precio en centavos, 
                    # asumiendo que ya lo tienes correcto.
                    "unit_amount": t['price'], 
                },
                "quantity": 1,
            }
            for t in tickets_list  # <-- ¡Usar tickets_list en lugar de tickets_en_carrito!
        ]

        # Añadir el Fee de servicio (este ya estaba correcto, asumiendo que total_fee está en centavos)
        line_items.append(
            {
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": "Fee de servicio"},
                    "unit_amount": total_fee_int,
                },
                "quantity": 1,
            }
        )

        metadata = {
            "customer_id": str(user_id),
            "tickets": str(tickets_ids),
            "event_id": str(event_id),
            "discount_code": discount_code if discount_code else None
        }

        # Añadir discount_code solo si total_discount != 0 y discount_code no está vacío

        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=line_items,
            mode="payment",
            discounts=[{"coupon": stripe_coupon_id}],
            success_url=f"{current_app.config['WEBSITE_FRONTEND_TICKERA']}/success?session_id=CHECKOUT_SESSION_ID",
            cancel_url=f"{current_app.config['WEBSITE_FRONTEND_TICKERA']}/confirm-purchase?query={event_id}",
            metadata=metadata,
        )

        return jsonify({"url": session.url, "status": "ok"}), 200
    except Exception as e:
        logging.error(f"Error creando sesión de Stripe: {str(e)}")
        return jsonify({"message": "Error creando sesión de pago", "status": "error"}), 500
    finally:
        db.session.close()


def bvc_api_verification_success(config, tickets_en_carrito, payment, customer, discount_code):

    try:
        total_discount = payment.sale.discount
        total_price = payment.sale.price

        tickets = []

        for ticket in tickets_en_carrito:
            discount = 0

            if total_discount > 0:
                proportion = ticket.price / total_price
                discount = int(round(total_discount * proportion, 2))

            log_for_emision = Logs(
                UserID=customer.CustomerID,
                Type='emision de boleto',
                Timestamp=datetime.now(),
                Details=f"Emisión de boleto {ticket.ticket_id} para la venta {payment.sale.sale_id}",
                SaleID=payment.sale.sale_id,
                TicketID=ticket.ticket_id
            )
            db.session.add(log_for_emision)

            serializer = config['serializer']
            token = serializer.dumps({'ticket_id': ticket.ticket_id, 'sale_id': payment.sale.sale_id})
            localizador = os.urandom(3).hex().upper()

            qr_link = f'{config["WEBSITE_FRONTEND_TICKERA"]}/tickets?query={token}'

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_link)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")

            qr_url = utils.newQR(img, ticket, s3)

            ticket.status = 'pagado'
            ticket.availability_status = 'Listo para canjear'
            ticket.emission_date = datetime.now().date()
            ticket.discount = discount
            ticket.saleLink = token
            ticket.saleLocator = localizador
            ticket.QRlink = qr_url # Guardar nuevas fotos en la base de datos respetando el orden

            sale_data = {
                'row': ticket.seat.row,
                'number': ticket.seat.number,
                'section': ticket.seat.section.name,
                'event': ticket.event.name,
                'venue': ticket.event.venue.name,
                'date': ticket.event.date_string,
                'hour': ticket.event.hour_string,
                'price': round(ticket.price / 100, 2),
                'discount': round(discount / 100, 2),
                'fee': round(ticket.fee / 100, 2),
                'total': round((ticket.price + ticket.fee - discount) / 100, 2),
                'link_reserva': qr_link,
                'localizador': localizador,
                'qr_image': qr_url
            }
            tickets.append(sale_data)
            
        IVA = config.get('IVA_PERCENTAGE', 0) / 100
        amount_no_IVA = int(round(payment.Amount / (1 + (IVA)/100), 2))
        amount_IVA = payment.Amount - amount_no_IVA
        BsDexchangeRate = customer.BsDExchangeRate
        total_fee = payment.sale.fee
        amount_discount = payment.sale.discount

        sale_data = {
            'sale_id': str(payment.sale.sale_id),
            'event': payment.sale.event_rel.name,
            'venue': payment.sale.event_rel.venue.name,
            'date': payment.sale.event_rel.date_string,
            'hour': payment.sale.event_rel.hour_string,
            'price': round(payment.sale.price*BsDexchangeRate / 10000, 2),
            'iva_amount': round(amount_IVA*BsDexchangeRate / 10000, 2),
            'net_amount': round(amount_no_IVA*BsDexchangeRate / 10000, 2),
            'total_abono': round(payment.Amount*BsDexchangeRate / 10000, 2),
            'payment_method': payment.PaymentMethod,
            'payment_date': payment.PaymentDate.strftime('%d-%m-%Y'),
            'reference': payment.Reference or 'N/A',
            'link_reserva': payment.sale.saleLink,
            'localizador': payment.sale.saleLocator,
            'exchange_rate_bsd': round(BsDexchangeRate/100, 2),
            'status': 'aprobado',
            'title': 'Tu pago ha sido procesado exitosamente',
            'subtitle': 'Gracias por tu compra, a continuación encontrarás los detalles de tu factura'
        }

        discount_code = discount_code.upper() if discount_code else None

        if discount_code:
            discount = Discounts.query.filter(Discounts.Code == discount_code).one_or_none()

        if discount:
            # Actualizar uso del descuento
            discount.UsedCount = (discount.UsedCount or 0) + 1
            payment.sale.discount_ref = discount.DiscountID

    
        # Actualizar métricas del evento
        stmt = (
            update(Event)
            .where(Event.event_id == int(payment.sale.event_rel.event_id))
            .values(
                total_sales = func.coalesce(Event.total_sales, 0) + 1,
                gross_sales = func.coalesce(Event.gross_sales, 0) + (int(payment.Amount) if payment.Amount is not None else 0),
                total_fees  = func.coalesce(Event.total_fees, 0) + (int(total_fee) if total_fee is not None else 0),
                total_discounts = func.coalesce(Event.total_discounts, 0) + (int(amount_discount) if amount_discount is not None else 0),
                total_discounts_tickera = (
                    func.coalesce(Event.total_discounts_tickera, 0)
                    + ((func.coalesce(Event.Fee, 0) * int(amount_discount) / 100) if amount_discount is not None else 0)
                )
            )
            .returning(Event.event_id)  # opcional, útil para confirmar
        )

        db.session.execute(stmt)

        db.session.commit()

        utils.sendqr_for_SuccessfulTicketsEmission(config, mail, customer, tickets)
        utils.sendnotification_for_CompletedPaymentStatus(config, db, mail, customer, tickets, sale_data)

        return {"message": "Métricas del evento actualizadas exitosamente", "status": "ok", "tickets": tickets}

    except Exception as e:
        # En caso de cualquier error (ej. la tabla fue bloqueada brevemente)
        logging.error(f"Error al actualizar métricas del evento: {e}")
        db.session.rollback() 
        return {"error": f"Fallo al actualizar DB: {e}", "status": "error"}