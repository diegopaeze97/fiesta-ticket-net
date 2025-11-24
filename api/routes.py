from flask import request, jsonify, Blueprint, make_response, session, current_app, g
from flask_jwt_extended import create_access_token,  set_access_cookies, jwt_required, verify_jwt_in_request
from werkzeug.security import  check_password_hash, generate_password_hash
from extensions import db, s3, stripe
from models import EventsUsers, Revoked_tokens, Event, Venue, Section, Seat, Ticket, Financiamientos, Sales, Logs, Payments, Active_tokens, VerificationCode, VerificationAttempt
from flask_jwt_extended import get_jwt, get_jti
from flask_mail import Message
import logging
from sqlalchemy.orm import joinedload, load_only
from sqlalchemy import and_, or_, func, not_
import os
import bleach
import pandas as pd
from datetime import datetime, timedelta, timezone
import eventos.utils as utils
import eventos.utils_whatsapp as WA_utils
from extensions import mail
from decorators.utils import optional_roles, roles_required
import signup.utils as signup_utils
import requests
import re
import calendar
from dateutil import parser
import time
from models import Event
from requests.adapters import HTTPAdapter, Retry
from decimal import Decimal, InvalidOperation
import random

api = Blueprint('api', __name__)

@api.route("/get-tickets", methods=["GET"])  # obtiene los tickets de un usuario
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def get_tickets():
    # obtener user id desde el JWT
    try:
        user_id = int(get_jwt().get("id"))
    except Exception:
        return jsonify({"message": "User ID not found in token", "status": "error", "redirect": "/login"}), 400

    raw_status = (request.args.get("status") or "").strip().lower()
    today_str = datetime.now().strftime("%Y-%m-%d")

    # opciones de carga eager para evitar N+1
    base_options = [
        load_only(
            Ticket.ticket_id,
            Ticket.availability_status,
            Ticket.price,
            Ticket.saleLink,
            Ticket.emission_date,
            Ticket.customer_id,
            Ticket.event_id,
            Ticket.seat_id,
            Ticket.sale_id,
        ),
        joinedload(Ticket.seat).
            load_only(Seat.row, Seat.number, Seat.section_id).
            joinedload(Seat.section).
            load_only(Section.name),
        joinedload(Ticket.event).
            load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string, Event.venue_id).
            joinedload(Event.venue).
            load_only(Venue.name)
    ]

    # base query: tickets del usuario con eager loading
    query = Ticket.query.options(*base_options).join(Event).filter(Ticket.customer_id == user_id)

    # filtrar en la DB según el parámetro status para reducir filas transferidas
    if raw_status == "listo para canjear":
        # tickets marcados como "Listo para canjear" y con fecha del evento >= hoy
        query = query.filter(
            and_(
                Ticket.availability_status == "Listo para canjear",
                Event.date_string >= today_str
            )
        )
    elif raw_status == "canjeado":
        # tickets ya canjeados o eventos con fecha pasada
        query = query.filter(
            or_(
                Ticket.availability_status == "canjeado",
                Event.date_string < today_str
            )
        )
    else:
        # comportamiento por defecto: cargar ambos estados
        query = query.filter(Ticket.availability_status.in_(["canjeado", "Listo para canjear"]))

    tickets = query.all()

    if not tickets:
        return jsonify({"message": "No tickets found for this user", "status": "error", "tickets": []}), 200

    tickets_data = []
    for ticket in tickets:
        # convertir price de forma segura
        try:
            price = float(ticket.price) / 100.0 if ticket.price is not None else None
        except Exception:
            price = None

        event = getattr(ticket, "event", None)
        seat = getattr(ticket, "seat", None)

        website = current_app.config.get('WEBSITE_FRONTEND_TICKERA', '')

        ticket_info = {
            "id": ticket.ticket_id,
            "status": raw_status,
            "price": price,
            "qrData": f'{website}/tickets?query={ticket.saleLink}',
            "event": {
                "event_id": getattr(event, "event_id", None),
                "name": getattr(event, "name", None),
                "date": f'{getattr(event, "date_string", None)}T12:00:00' if getattr(event, "date_string", None) else None,
                "hour": getattr(event, "hour_string", None),
                "venue": event.venue.name if (event and getattr(event, "venue", None)) else None
            },
            "seat": {
                "section": seat.section.name if (seat and getattr(seat, "section", None)) else None,
                "row": seat.row if seat else None,
                "number": seat.number if seat else None
            },
            "emission_date": ticket.emission_date.isoformat() if getattr(ticket, "emission_date", None) else None
        }
        tickets_data.append(ticket_info)

    #return jsonify({"tickets": tickets_data, "status": "ok"}), 200
    return jsonify({"tickets": [], "status": "ok"}), 200

#Oauth 2.0 con google
@api.route('/auth/google', methods=['POST'])
def google_auth():
    data = request.json
    access_token = data.get('access_token')

    if not access_token:
        return jsonify({"message": "No se proporcionó Access Token", "status": "error"}), 400

    # 1. VERIFICACIÓN: Usar el token para obtener la información del usuario de Google
    try:
        # Endpoint de Google para obtener info del usuario con el Access Token
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        userinfo_response.raise_for_status() # Lanza excepción para códigos de error HTTP

        google_user_data = userinfo_response.json()

        user_email = google_user_data.get('email', '').lower().strip()

        if not user_email:
            return jsonify({"message": "No se pudo obtener el correo electrónico del usuario", "status": "error"}), 400

    except requests.RequestException as e:
        logging.error(f"Error al verificar token con Google: {e}")
        return jsonify({"message": "Token de Google inválido o expirado", "status": "error"}), 401
    
    # 2. LÓGICA DE NEGOCIO (Login/Registro)
    try:
        user_id, role = find_or_create_user(google_user_data, db, EventsUsers, Logs)

        if not isinstance(user_id, int):
            # Si find_or_create_user retornó un error
            return jsonify({"message": user_id.get("error", "Error al intentar autenticar con Google"), "status": "error"}), 400
        
    except Exception as e:
        logging.error(f"Error en find_or_create_user (Google): {e}")
        return jsonify({"message": "Error interno al procesar el usuario", "status": "error"}), 500
    
    # 3. CREAR TOKEN DE SESIÓN PARA EL FRONTEND
    # Suponiendo que tienes una función para manejar la creación de tokens de sesión:
    access_token = create_access_token(
        identity=str(user_id), 
        additional_claims={'role': 'customer', 'username': user_email, 'status': 'verified', 'id': user_id}
    )
    
    # Lógica para crear el Active_token (similar a tu login)
    access_jti = get_jti(access_token)
    newtoken = Active_tokens(CustomerID=user_id, jti=access_jti)
    db.session.add(newtoken)
    db.session.commit()
    
    # 4. RESPUESTA AL FRONTEND
    return jsonify({
        "message": "Login exitoso via Google",
        "token": access_token,
        "user_id": user_id,
        "role": role,
        "username": user_email,
        "status": "ok"
    })



def find_or_create_user(google_user_data, db, EventsUsers, Logs):
    """
    Busca un usuario por email o lo crea automáticamente.
    Diseñado para el Social Login (Google).

    :param email: Email del usuario proporcionado por Google.
    :param full_name: Nombre completo del usuario proporcionado por Google.
    :param db: Objeto de sesión de la base de datos (db.session).
    :param EventsUsers: Modelo ORM de la tabla de usuarios.
    :param Logs: Modelo ORM para el registro de logs.
    :param signup_utils: Módulo con utilidades de registro (incluye validate_newuser).
    :param current_app: Objeto de la aplicación Flask (para configuraciones).
    :return: CustomerID del usuario logueado.
    """
    today = datetime.now()
    email = google_user_data['email'].lower().strip()
    
    # Intenta dividir el nombre completo en Nombre y Apellido (simplificado)
    firstname = google_user_data.get('given_name', '').strip()
    lastname = google_user_data.get('family_name', '').strip()
    picture = google_user_data.get('picture', '').strip()
    
    # Genera un hash de una contraseña aleatoria/ficticia para cumplir con la estructura DB.
    # Esto evita que el usuario pueda usar el login tradicional sin un restablecimiento.
    # NOTA: Reemplazar 'RANDOM_SECURE_STRING' con una generación real si es necesario.
    secuencia_random = str(random.getrandbits(128))
    random_password_hash = generate_password_hash(secuencia_random + str(datetime.now()))

    try:
        # 1. Buscar usuario existente (incluyendo 'passive_customer' o 'unverified')
        user = db.session.query(EventsUsers).filter(
            EventsUsers.Email == email
        ).one_or_none()

        if user is not None:
            if user.status == 'suspended':
                return {"error": "Usuario baneado"}
            # 1a. Si el usuario es 'passive_customer' o 'unverified', lo actualizamos a 'customer'
            # y completamos los campos básicos.
            if user.role == 'passive_customer' or user.status == 'unverified':
                
                # Actualizar campos mínimos con la info de Google
                user.strikes = 0
                user.status = 'verified' 
                user.role = 'customer' if user.role == 'passive_customer' else user.role
                user.MainPicture = picture if picture else user.MainPicture

                log_for_update = Logs(
                    UserID=user.CustomerID,
                    Type='actualizacion usuario',
                    Timestamp=datetime.now(),
                    Details=f"Usuario Google actualizó cuenta: {firstname} {lastname} ({email})",
                )
                db.session.add(log_for_update)

                db.session.commit()
                return user.CustomerID, user.role
            
            # 1b. Si el usuario ya es 'customer' (u otro rol activo), simplemente lo logueamos.
            elif user.role != 'passive_customer':
                # El usuario ya existe y está activo, no necesita actualización de datos.
                return user.CustomerID, user.role

        else:
            # 2. El usuario NO existe, lo creamos.
            new_user = EventsUsers(
                Email=email,
                Password=random_password_hash,
                FirstName=firstname,
                LastName=lastname,
                MainPicture=picture,
                PhoneNumber=None,           # Campo vacío/nulo
                Identification=None,        # Campo vacío/nulo
                status='verified',   
                role='customer',
                strikes=0,
                Joindate=today
            )
            db.session.add(new_user)
            db.session.flush() # Obtener CustomerID

            log_for_new_user = Logs(
                UserID=new_user.CustomerID,
                Type='nuevo usuario (Google)',
                Timestamp=datetime.now(),
                Details=f"Nuevo usuario registrado via Google: {firstname} {lastname} ({email})",
            )
            db.session.add(log_for_new_user)

            db.session.commit()
            return new_user.CustomerID, 'customer'

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error en find_or_create_user (Google): {e}")
        return {"error": "Error interno al procesar el usuario"}