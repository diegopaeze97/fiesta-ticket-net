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
import eventos.services as eventos_services
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
import json

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
                Event.hour_string,
                Event.type_of_event
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
        
        tickets_list = []
        if event.from_api:

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
                allowed_methods=frozenset(['GET', 'POST']),
                
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
            verify = current_app.config.get("REQUESTS_VERIFY", 'True') == 'True'

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
                tickets = response.json().get("tickets", [])
            else:
                return jsonify({"message": "Error al obtener el mapa de asientos desde Tickera"}), 500
            
        else: # evento local, no desde API externa
            tickets_db = Ticket.query.options(
                joinedload(Ticket.seat).load_only(Seat.section_id, Seat.row, Seat.number),
                joinedload(Ticket.seat).joinedload(Seat.section).load_only(Section.name, Section.accepted_payment_methods),
                load_only(Ticket.ticket_id, Ticket.status, Ticket.price, Ticket.expires_at)
            ).filter(
                Ticket.event_id == int(event.event_id)
            ).all()

            tickets = []
            for t in tickets_db:
                accepted_payment_methods =str(t.seat.section.accepted_payment_methods) if t.seat and t.seat.section and t.seat.section.accepted_payment_methods else 'all'
                currency = utils.accepts_all_payment_methods(accepted_payment_methods)
                tickets.append({
                    "ticket_id": t.ticket_id,
                    "svg_id": (t.seat.section.name + '-' + t.seat.row + str(t.seat.number)).lower() if not event.label_inverted else (t.seat.section.name + '-' + str(t.seat.number) + t.seat.row).lower(),
                    "status": t.status,
                    "row": t.seat.row if t.seat else '',
                    "number": t.seat.number,
                    "section": t.seat.section.name if t.seat and t.seat.section else '',
                    "price": t.price,
                    "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                    "currency": currency
                })  
        

        

        now = datetime.now(timezone.utc)  # Siempre en UTC
        now_ts = calendar.timegm(now.utctimetuple())

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
                for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                    try:
                        expires_dt = datetime.strptime(expires_raw, fmt)
                        expires_ts = calendar.timegm(expires_dt.utctimetuple())
                        break
                    except Exception:
                        continue

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
                "currency": t.get("currency", "all"),
            })
        
        total_end = time.perf_counter()

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
            "type_of_event": event.type_of_event if hasattr(event, 'type_of_event') else None,
        }

        # ---------------------------------------------------------------
        # 5️⃣ Obtenemos la tasa de cambio actual en BsD (si es necesario)
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



        return jsonify(
            tickets=tickets_list,
            venue_map=event.SVGmap,
            event=event_details,
            status="ok",
            BsDexchangeRate=BsDexchangeRate,
        ), 200

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

        
        if event.from_api: #si el evento es de la API externa
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
            verify = current_app.config.get("REQUESTS_VERIFY", 'True') == 'True'

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

            tickets_r = response.json().get("tickets", [])
        else:
            tickets_db = Ticket.query.options(
                joinedload(Ticket.seat).load_only(Seat.section_id, Seat.row, Seat.number),
                joinedload(Ticket.seat).joinedload(Seat.section).load_only(Section.name),
                load_only(Ticket.ticket_id, Ticket.status, Ticket.expires_at)
            ).filter(
                Ticket.event_id == int(event.event_id),
                or_(Ticket.status == 'disponible', Ticket.status == 'en carrito')
            ).all()
            # convertir a formato similar al de la API externa
            tickets_db_converted = []
            for t in tickets_db:
                tickets_db_converted.append({
                    "ticket_id": t.ticket_id,
                    "status": t.status,
                    "row": t.seat.row if t.seat else '',
                    "number": t.seat.number,
                    "section": t.seat.section.name if t.seat and t.seat.section else '',
                    "expires_at": t.expires_at.isoformat() if t.expires_at else None
                })
            tickets_r = tickets_db_converted

        ticket_map = {int(t['ticket_id']): t for t in tickets_r if t.get('status') in ['disponible', 'en carrito']}

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

        # expire_at (ISO, UTC 'Z') — asegurar formato y rango (<= 24h por ejemplo)
        now = datetime.now(timezone.utc)
        expire_dt_aware = now + timedelta(minutes=10)
        expire_at_str = expire_dt_aware.replace(microsecond=0).isoformat() + "Z"

        if event.from_api: #si el evento es de la API externa
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

            # Construir payload
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

            verify = current_app.config.get("REQUESTS_VERIFY", 'True') == 'True'

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
        if event.from_api:
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
        else:
            for ticket_sistema in tickets_sistema:
                for s in selected_seats:
                    if int(ticket_sistema.ticket_id) == int(s['ticket_id']):
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
            .load_only(Section.name, Section.accepted_payment_methods),
            # Load the event basic fields
            joinedload(Ticket.event).load_only(
                Event.Fee, Event.name, Event.date_string, Event.hour_string, Event.from_api, Event.label_inverted
            ),
            # Load venue from the event
            joinedload(Ticket.event).joinedload(Event.venue).load_only(Venue.venue_id, Venue.name),
            # Load additional features from the event
            joinedload(Ticket.event).joinedload(Event.additional_features)
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

        accepted_payment_methods = utils.get_accepted_payment_methods(tickets_en_carrito)

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
            
        #si no hay métodos de pago en común, retornar error
        if accepted_payment_methods == []:
            return jsonify({"message": "No hay métodos de pago disponibles para los asientos seleccionados", "status": "error"}), 400
            
        number_json = None
            
        if customer.PhoneNumber:
            number_json = {
                "country_code": customer.CountryCode,
                "number": customer.PhoneNumber
            }
        else:
            number_json = None

        additional_features = event_details.additional_features if hasattr(event_details, 'additional_features') else None

        additional_features_list = []
        if additional_features:
            for additional_feature in additional_features:
                if additional_feature.accepted_payment_methods != 'all':
                    accepted_methods = additional_feature.accepted_payment_methods.split(',')
                    if not any(method in accepted_payment_methods for method in accepted_methods):
                        continue  # saltar esta característica si no hay métodos de pago en común
                if additional_feature.FeaturePrice <= 0:
                    continue  # saltar características con precio no positivo
                if additional_feature.Active != True:
                    continue  # saltar características inactivas
                additional_features_list.append({
                    "FeatureID": additional_feature.FeatureID,
                    "FeatureName": additional_feature.FeatureName,
                    "FeatureDescription": additional_feature.FeatureDescription,
                    "FeaturePrice": additional_feature.FeaturePrice,
                    "FeatureCategory": additional_feature.FeatureCategory
                })

        event_dict  = {  
            "name": event_details.name,
            "date": event_details.date_string,
            "hour": event_details.hour_string,
            "place": event_details.venue.name if event_details.venue else None
        }

        user_info = {
            "phone": customer.PhoneNumber,
            "identification": customer.Identification,
            "address": customer.Address
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
            "user_info": user_info,
            "accepted_payment_methods": accepted_payment_methods,
            "additional_features": additional_features_list,
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

    addons = request.json.get('addons', [])
    

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
    
    accepted_payment_methods = utils.get_accepted_payment_methods(tickets_en_carrito)

    if payment_method not in accepted_payment_methods and accepted_payment_methods != ['all']:
        return jsonify({"message": "El método de pago seleccionado no está disponible para los asientos en el carrito"}), 400   

    now = datetime.now(timezone.utc)  # Siempre en UTC
    for t in tickets_en_carrito:
        # 1. Convierte t.expires_at a aware ASUMIENDO que es UTC
        if t.expires_at and t.expires_at.tzinfo is None:
            expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at_aware = t.expires_at # Ya tiene info de zona horaria
        if not expires_at_aware or expires_at_aware < now:
            return jsonify({"message": "Tu reserva ha caducado"}), 400
        
    total_discount = 0
    discount_id = None
        
    if event.from_api: #si el evento es de la API externa

        # ----------------------------------------------------------------
        # 5️⃣ Bloquear en Tickera (antes de modificar BD local)
        # ----------------------------------------------------------------
        url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/block-tickets"

        # Normalizar event id
        event_id = str(event.event_id_provider).strip()
        if not event_id or not event_id.isdigit() or len(event_id) > 64:
            raise ValueError("event_id inválido")
        
        tickets_payload = utils.clean_tickets(tickets_en_carrito)

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

        verify = current_app.config.get("REQUESTS_VERIFY", 'True') == 'True'
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

        serializer = current_app.config['serializer']
        token = serializer.dumps({'user_id': user_id})
        qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={token}'
        localizador = os.urandom(3).hex().upper()

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
            discount_ref=discount_id,
            saleLink = token,
            saleLocator = localizador
        )
        db.session.add(sale)
        db.session.flush()

        validated_addons = []
        total_price_addons = 0
        
        if addons:
            
            validation_response = utils.validate_addons(addons, event, payment_method, tickets_en_carrito)
            if isinstance(validation_response, tuple):  # Si es una respuesta de error
                logging.info(validation_response)
                return validation_response  # Retorna el error directamente
            
            validated_addons = validation_response

            for addon in validated_addons:
                purchased_feature = utils.record_purchased_feature(
                    sale.sale_id,
                    int(addon["FeatureID"]),
                    int(addon["Quantity"]),
                    int(addon["FeaturePrice"])
                )
                db.session.add(purchased_feature)
                total_price_addons += int(addon["Quantity"]) * int(addon["FeaturePrice"])

            total_price += total_price_addons
            sale.price = total_price
            db.session.flush()

        # Actualizar tickets
        for t in tickets_en_carrito:
            t.status = payment_status
            t.sale_id = sale.sale_id
            t.expires_at = None

        today = datetime.utcnow().date()
        total_amount = total_price + total_fee - total_discount
        MontoBS = int((total_amount) * customer.BsDExchangeRate / 100)

        payment = Payments(
            SaleID=sale.sale_id,
            Amount=total_amount,
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
        db.session.flush()

        # ----------------------------------------------------------------
        # 7️⃣ Enviar notificación según método de pago
        # ----------------------------------------------------------------

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
            'add_ons': validated_addons if validated_addons else None,
            'is_package_tour': event.type_of_event == 'paquete_turistico',
            'currency': 'usd'
        }

        ENVIRONMENT = current_app.config.get('ENVIRONMENT').lower()

        if payment_method == "pagomovil":
            sale_data.update({
                'status': 'pagado',
                'title': 'Estamos procesando tu abono',
                'subtitle': 'Te notificaremos una vez que haya sido aprobado',
                'due': round(0, 2),
            })

            payment_data = {}
            payment_data['fecha'] = today.strftime('%d/%m/%Y') if ENVIRONMENT in ['production', 'development'] else '07/11/2025'
            payment_data['banco'] = bank_code
            payment_data['telefonoP'] = phone_number
            payment_data['referencia'] = payment_reference
            
            if ENVIRONMENT == 'development': # para pruebas en desarrollo
                MontoBS = MontoBS/1000

            payment_data['monto'] = float(round(MontoBS/100, 2)) if ENVIRONMENT in ['production', 'development'] else 15.00
            
            try:
                response= vol_utils.verify_p2c(payment_data)
                data = response[0]

                if data['status_code'] == 200:
                    payment.Status = 'pagado'
                    sale.status = 'pagado'
                    sale.StatusFinanciamiento = 'pagado'
                    sale.paid = total_abono

                    notify_customer =  eventos_services.bvc_api_verification_success(current_app.config, tickets_en_carrito, payment, customer, discount_code, validated_addons, total_price_addons)

                    if notify_customer['status'] == 'error':
                        logging.error(f"Error enviando notificación al cliente: {notify_customer['message']}")
                    
                    bank_obtained_ref = str(data['decrypted'].get('referencia')) if data.get('decrypted') else None
                    bank_obtained_ref_no_zeros = bank_obtained_ref.lstrip("0") if bank_obtained_ref else None

                    new_reference = BankReferences(
                        reference=bank_obtained_ref_no_zeros,
                    )
                    db.session.add(new_reference)
                    db.session.commit()

                    utils.notify_admins_automatic_pagomovil_verification(current_app.config, db, mail, customer, sale, payment, tickets_en_carrito, MontoBS)
                    
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
                "section": section_name.replace('20_', ' '),
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
            # Parse ticket ids preserving order
            raw_ids = sale.ticket_ids.split('|') if sale.ticket_ids and '|' in sale.ticket_ids else ([sale.ticket_ids] if sale.ticket_ids else [])
            ticket_ids = [int(t) for t in raw_ids if t]

            if ticket_ids:
                tickets_q = Ticket.query.options(
                    load_only(Ticket.ticket_id, Ticket.price, Ticket.status),
                    joinedload(Ticket.seat)
                        .load_only(Seat.row, Seat.number, Seat.section_id)
                        .joinedload(Seat.section)
                        .load_only(Section.name)
                ).filter(Ticket.ticket_id.in_(ticket_ids)).all()

                tickets_map = {t.ticket_id: t for t in tickets_q}

                # Preserve original order from sale.ticket_ids
                for tid in ticket_ids:
                    t = tickets_map.get(tid)
                    if not t:
                        continue
                    seat = t.seat
                    section = seat.section.name if seat and seat.section else None
                    tickets.append({
                        'ticket_id': t.ticket_id,
                        'price': round(t.price/100, 2),
                        'status': t.status,
                        'section': section.replace('20_',' '),
                        'row': seat.row if seat else None,
                        'number': seat.number if seat else None
                    })

            features = []

            if sale.purchased_features:
                purchased_features = sale.purchased_features
                

                for feature_entry in purchased_features:
                    characteristics = feature_entry.feature
                    features.append({
                        'FeatureID': feature_entry.FeatureID,
                        'FeatureName': characteristics.FeatureName,
                        'FeatureDescription': characteristics.FeatureDescription,
                        'FeaturePrice': round(feature_entry.PurchaseAmount/100, 2),
                        'Quantity': feature_entry.Quantity
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
            information['subtotal'] = round((sale.price)/100, 2)
            information['features'] = features

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


@events.route("/create-stripe-checkout-session", methods=["POST"])
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def create_stripe_checkout_session():
    user_id = get_jwt().get("id")
    event_id = request.args.get('query', '')
    discount_code = request.args.get('discount_code', '')

    addons = request.json.get('addons', [])

    # ----------------------------------------------------------------
    # 1️⃣ Validaciones iniciales
    # ----------------------------------------------------------------
    if not all([user_id, event_id]):
        logging.info("Faltan parámetros obligatorios")
        return jsonify({"message": "Faltan parámetros obligatorios"}), 400
    
    try:
        totals = eventos_services.preprocess_validation(user_id, event_id, addons, discount_code, payment_method='stripe')

        if totals.get("status") == "error":
            return jsonify({"message": totals.get("message"), "status": "error"}), 400
        
        total_discount = totals["total_discount"]
        validated_addons = totals["validated_addons"]
        event = totals["event"]
        tickets_ids = totals["tickets_ids"]
        tickets_list = totals["tickets"]
        total_fee_int = totals["total_fee"]

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
                    "product_data": {"name": f"Asiento: {t['section'].replace('20_', ' ')} - {t['seat']} - {event.name}"},
                    "unit_amount": t['price'], 
                },
                "quantity": 1,
            }
            for t in tickets_list  # <-- ¡Usar tickets_list en lugar de tickets_en_carrito!
        ]

        # Añadir items de complementos (addons) si existen
        if validated_addons:
            for addon in validated_addons:
                if addon["Quantity"] > 0:
                    line_items.append(
                        {
                            "price_data": {
                                "currency": "usd",
                                "product_data": {"name": f"Complemento: {addon["FeatureName"]}"},
                                "unit_amount": addon["FeaturePrice"],
                            },
                            "quantity": addon["Quantity"],
                        }
                    )


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
            "discount_code": discount_code if discount_code else None,
            "addons": str(validated_addons) if validated_addons else None
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
    
@events.route('/get-debitoinmediato-code', methods=['POST'])
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def get_debitoinmediato_code():
    user_id = get_jwt().get("id")
    data = request.get_json()

    event_id = data.get('event_id')
    discount_code = data.get('discount_code', '')
    payment_method = data.get("paymentMethod")
    cedula_type = data.get("cedula_type")
    cedula = data.get("cedula")
    phone_number = data.get("telefono")
    bank = data.get("banco")
    carrito_tickets_frontend = data.get("carrito", [])

    # ----------------------------------------------------------------
    # 1️⃣ Validaciones iniciales
    # ----------------------------------------------------------------
    if not all([user_id, payment_method, event_id, cedula_type, cedula, phone_number, bank]):
        return jsonify({"message": "Faltan parámetros obligatorios"}), 400
    
    if len(carrito_tickets_frontend) == 0:
        return jsonify({"message": "El carrito de compras está vacío"}), 400
    
    carrito_tickets_frontend_ids = [str(ticket.get("ticket_id")) for ticket in carrito_tickets_frontend if ticket.get("ticket_id")]

    # ----------------------------------------------------------------
    # 2️⃣ Validar información del pago
    # ----------------------------------------------------------------
    if payment_method != "debito inmediato":
        return jsonify({"message": "Método de pago no válido para este endpoint"}), 400

    if not utils.venezuelan_phone_pattern.match(phone_number):
        return jsonify({"message": "Número de teléfono no válido"}), 400
    
    lista_de_bancos_venezolanos = [banco for banco in bancos_venezolanos.keys()]

    if bank.upper() not in lista_de_bancos_venezolanos:
        return jsonify({"message": "Banco no válido"}), 400
    
    bank_code = bancos_venezolanos.get(bank.upper())

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
        carrito_tickets_backend_ids = []
        total_price = 0
        total_discount = 0

        for t in tickets_en_carrito:
            # 1. Convierte t.expires_at a aware ASUMIENDO que es UTC
            if t.expires_at and t.expires_at.tzinfo is None:
                expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
            else:
                expires_at_aware = t.expires_at # Ya tiene info de zona horaria
            if not expires_at_aware or expires_at_aware < now:
                return jsonify({"message": "Tu reserva ha caducado"}), 400
            carrito_tickets_backend_ids.append(str(t.ticket_id))
            total_price += t.price

        # Validar que los tickets del frontend coincidan con los del backend
        if set(carrito_tickets_frontend_ids) != set(carrito_tickets_backend_ids):
            return jsonify({"redirect": f"/events/get-paymentdetails?query={event_id}&discount_code={discount_code}"}), 400
        
        
        ### validamos el descuento
        if discount_code:
            discount_validation = utils.validate_discount_code(discount_code, customer, event, tickets_en_carrito, 'buy')
            if not discount_validation.get('status'):
                return jsonify({"message": discount_validation.get('message', 'Error en el descuento')}), 400
            else:
                total_discount = discount_validation.get('total_discount', 0)
    
        total_fee = (event.Fee or 0) * total_price / 100

        if total_discount > (total_price + total_fee):
            total_discount = total_price + total_fee

        total_amount = total_price + total_fee - total_discount

        MontoBS = int((total_amount) * customer.BsDExchangeRate / 100)

        ENVIRONMENT = current_app.config.get('ENVIRONMENT').lower()
        
        if ENVIRONMENT == 'development': # para pruebas en desarrollo
            MontoBS = MontoBS/1000

        payment_data = {}

        payment_data['nombreBen'] = f"{customer.FirstName} {customer.LastName}"
        payment_data['tipoPersonaBen'] = cedula_type
        payment_data['cirifBen'] = cedula
        payment_data['codBancoBen'] = bank_code
        payment_data['cuentaBen'] = phone_number
        payment_data['tipoDatoCuentaBen'] = 'CELE' # siempre es celular
        payment_data['concepto'] = 'FIESTA TICKET'
        payment_data['monto'] = float(round(MontoBS/100, 2)) if ENVIRONMENT in ['production', 'development'] else 300.5
        
        response= vol_utils.get_debitoinmediato_code(payment_data)
        data = response[0]

        if data['status_code'] != 200:
            logging.error(f"Error al enviar codigo de autorizacion: {data}")
            return jsonify({"message": "El código de validación no pudo ser enviado, por favor verifique los datos proporcionados e intente nuevamente", "status": "error"}), 400

        return jsonify({"message": "código validador enviado con éxito", "status": "ok"}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error registrando venta o pago: {str(e)}")
        return jsonify({"message": "Error interno al enviar codigo validador", "status": "error"}), 500
    finally:
        db.session.close()

@events.route('/validate-c2p', methods=['POST'])
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def validate_c2p():
    """
    Endpoint para validar transacciones de PagoMóvil C2P en tiempo real.
    
    Este endpoint recibe los datos de una transacción de PagoMóvil y valida
    su autenticidad consultando con el banco en tiempo real.
    
    Request Body:
    {
        "referencia": "123456",      # Referencia de la transacción
        "fecha": "31/12/2024",       # Fecha en formato DD/MM/YYYY
        "banco": "0102",             # Código del banco
        "telefono": "04121234567",   # Teléfono del pagador
        "monto": 100.50              # Monto de la transacción
    }
    
    Returns:
        JSON con el resultado de la validación
    """
    try:
        data = request.get_json(silent=True) or {}
        
        # Extraer parámetros
        token_validador = data.get("token", "").strip()
        banco = data.get("banco", "").strip()
        telefono = data.get("telefono", "").strip()
        cedula = data.get("cedula", "").strip()
        nacionalidad = data.get("nacionalidad", "").strip()
        event_id = request.args.get("query", "").strip()
        discount_code = request.args.get("discount_code", "").strip()
        addons = data.get("addons", [])
        
        # Validaciones básicas
        if not all([token_validador, banco, telefono, cedula, nacionalidad]):
            missing = []
            if not token:
                missing.append("token")
            if not banco:
                missing.append("banco")
            if not telefono:
                missing.append("telefono")
            if not cedula:
                missing.append("cedula")
            if not nacionalidad:
                missing.append("nacionalidad")
            
            return jsonify({
                "status": "error",
                "message": "Faltan parámetros obligatorios",
                "missing": missing
            }), 400
        
        # Validar formato del teléfono (debe ser un número venezolano)
        if not utils.venezuelan_phone_pattern.match(telefono):
            return jsonify({
                "status": "error",
                "message": "Número de teléfono no válido. Debe ser un número venezolano."
            }), 400
        
        identification = f"{nacionalidad}{cedula}"
        
        if not utils.cedula_pattern.match(identification):
            return jsonify({
                "status": "error",
                "message": "Cédula no válida. Debe ser una cédula venezolana."
            }), 400
        
        # Validar que el banco esté en la lista de bancos venezolanos
        if banco.upper() not in bancos_venezolanos:
            return jsonify({
                "status": "error",
                "message": "Código de banco no válido"
            }), 400
        
        bank_code = bancos_venezolanos.get(banco.upper())

        # Obtenemos el monto desde el carrito del usuario
        user_id = get_jwt().get("id")

        totals = eventos_services.preprocess_validation(user_id, event_id, addons, discount_code, payment_method='c2p')

        if type(totals) == tuple:
            return totals
        
        tickets_en_carrito = totals["tickets_en_carrito"]
        
        validated_addons = totals["validated_addons"]
        event = totals["event"]
        tickets_ids = totals["tickets_ids"]
        customer = totals["customer"]
        total_price = totals["total_price"]
        total_price_tickets = totals["total_price_tickets"]
        total_amount_to_pay = totals["total_amount_to_pay"]
        total_discount = totals["total_discount"]
        total_fee = totals["total_fee"]
        discount_id = totals["discount_id"]

        #####
        #ahora calculamos el monto en BsD
        #####
        MontoBS = float((total_amount_to_pay) * customer.BsDExchangeRate / 10000) #extra ceros por el tema de centavos
        
        # Validar que el monto sea un número positivo
        try:
            if MontoBS <= 0:
                return jsonify({
                    "status": "error",
                    "message": "El monto debe ser mayor a cero"
                }), 400
        except (ValueError, TypeError):
            return jsonify({
                "status": "error",
                "message": "Monto inválido"
            }), 400
        
        today = datetime.now().strftime("%d/%m/%Y")

        ENVIRONMENT = current_app.config.get('ENVIRONMENT').lower()
            
        if ENVIRONMENT == 'development': # para pruebas en desarrollo
            MontoBS = MontoBS/1000
        
        # Preparar datos para la validación
        payment_data = {
            "nacionalidad": nacionalidad,
            "cedula": cedula,
            "banco": bank_code,
            "telefono": telefono,
            "monto": float(round(MontoBS, 2)) if ENVIRONMENT in ['production', 'development'] else 0.05,
            "Token": token_validador
        }
        
        logging.info(f"Validando transacción C2P - Monto: {MontoBS}")
        
        # Llamar a la función de validación en vol_api.functions
        validation_result, status_code = vol_utils.validate_c2p_realtime(payment_data)

        # ----------------------------------------------------------------
        # 6️⃣ Aplicar cambios locales (una sola transacción)
        # ----------------------------------------------------------------

        ticket_str_ids = tickets_ids
        serializer = current_app.config['serializer']
        token = serializer.dumps({'user_id': user_id})
        qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={token}'
        localizador = os.urandom(3).hex().upper()

        # Crear registro de venta
        sale = Sales(
            ticket_ids=ticket_str_ids,
            price=total_price,
            paid=total_amount_to_pay,
            user_id=user_id,
            status='pagado',
            created_by=user_id,
            StatusFinanciamiento='pagado',
            event=event.event_id,
            fee=total_fee,
            discount=total_discount,
            ContactPhoneNumber=telefono,
            discount_ref=discount_id,
            saleLink = qr_link,
            saleLocator = localizador
        )
        db.session.add(sale)
        db.session.flush()

        payment = Payments(
            SaleID=sale.sale_id,
            Amount=total_amount_to_pay,
            PaymentDate=today,
            PaymentMethod='c2p',
            Status='pagado',
            CreatedBy=user_id,
            MontoBS=MontoBS,
            Bank=banco,
            PhoneNumber=telefono,
        )
        
        db.session.add(payment)
        db.session.flush()
            
        # Actualizar tickets
        for t in tickets_en_carrito:
            t.status = "pagado"
            t.sale_id = sale.sale_id
            t.expires_at = None

        db.session.flush()
        
        # Procesar el resultado
        if status_code == 200 :

            if event.from_api: #si el evento es de la API externa
                tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
                tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

                if not tickera_id or not tickera_api_key:  
                    return jsonify({"message": "Error interno: credenciales de Tickera no configuradas"}), 500
                # ----------------------------------------------------------------
                # 5️⃣ Bloquear en Tickera (antes de modificar BD local)
                # ----------------------------------------------------------------
                url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/block-tickets"

                # Normalizar event id
                event_id = str(event.event_id_provider).strip()
                if not event_id or not event_id.isdigit() or len(event_id) > 64:
                    raise ValueError("event_id inválido")
                
                tickets_payload = utils.clean_tickets(tickets_en_carrito)

                if not tickets_payload:
                    raise ValueError("No hay tickets válidos para bloquear")
                
                if discount_code and total_discount > 0:
                    validated_discount = utils.validate_discount_code(discount_code, customer, event, tickets_en_carrito, 'block')
                    if not validated_discount["status"]:
                        return jsonify({"message": "Código de descuento inválido"}), 400
 
                    tickets_payload = validated_discount['tickets']

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

                verify = current_app.config.get("REQUESTS_VERIFY", 'True') == 'True'
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

            validation_details = validation_result.get("decrypted", {})

            referenciaMovimiento = validation_details.get("referenciaMovimiento", "")
            referenciaOriginal = validation_details.get("referenciaOriginal", "")

            ### actualizamos payment

            payment.referenciaOriginal = referenciaOriginal
            payment.Reference = referenciaMovimiento

            db.session.flush()

            approval = eventos_services.ticket_approval_c2p(tickets_en_carrito, total_discount, total_price_tickets, validated_addons, payment, customer, current_app.config, discount_code)

            if type(approval) == tuple:
                db.session.rollback()
                return approval
            
            db.session.commit()

            # Transacción válida
            return jsonify({
                "status": "ok",
                "validated": True,
                "message": "Transacción validada exitosamente",
                "transaction_data": validation_result.get("transaction_data", {})
            }), 200
        elif status_code != 200 and validation_result.get("decrypted"):
            error = validation_result["decrypted"].get("mensaje", "Transacción no válida o no encontrada")
            # Transacción no válida o no encontrada
            return jsonify({
                "status": "error",
                "validated": False,
                "message": error,
            }), 400
        else:
            # Error en la validación
            return jsonify({
                "status": "error",
                "validated": False,
                "message": validation_result.get("error", "Error al validar la transacción"),
                "error": validation_result.get("error", "Error desconocido")
            }), status_code
    
    except Exception as e:
        logging.exception(f"Error en validate-c2p: {e}")
        return jsonify({
            "status": "error",
            "message": "Error interno al validar transacción",
            "detail": str(e)
        }), 500
    finally:
        db.session.close()


