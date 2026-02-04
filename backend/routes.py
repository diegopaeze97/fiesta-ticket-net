from flask import request, jsonify, Blueprint, make_response, session, current_app, render_template
from flask_jwt_extended import create_access_token, jwt_required
from werkzeug.security import  check_password_hash, generate_password_hash
from extensions import db, s3
from models import EventsUsers, Revoked_tokens, Event, Venue, Section, Seat, Ticket, Liquidations, Sales, Logs, Payments, Active_tokens, Discounts, Providers, EventUserAccess, AdditionalFeatures, PurchasedFeatures
from flask_jwt_extended import get_jwt, get_jti
from flask_mail import Message
import logging
from sqlalchemy.orm import joinedload, load_only
from sqlalchemy import and_, or_, func, case, update
import os
import bleach
import pandas as pd
from datetime import datetime, timedelta, timezone
import eventos.utils as utils
from extensions import mail
from decorators.utils import roles_required
import signup.utils as signup_utils
import eventos.utils_whatsapp as WA_utils
import requests
import re
import time
import calendar
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import backend.utils as utils_backend


backend = Blueprint('backend', __name__)

UPLOAD_FOLDER = "uploads/seats"

# Asegura que el folder exista
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@backend.route('/login', methods=['POST'])
def login():
    email = request.json.get("email")
    password = request.json.get("password")

    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Por favor proporciona email y contraseña.'}), 400

    email = email.strip()
    password = password.strip()

    try:
        user = db.session.query(EventsUsers).filter_by(Email=email.lower()).one_or_none()

        if user is None:
            return jsonify({'status': 'error', 'message': 'El usuario no existe, verifique e intente nuevamente.'}), 404

        if check_password_hash(user.Password, password) and user.status.lower() == 'eliminated':
            return jsonify({'status': 'error', 'message': 'Tu cuenta ha sido eliminada. Si tienes alguna pregunta o necesitas ayuda, por favor contacta al administrador.'})

        if user.role == 'passive_customer':
            return jsonify({'status': 'error', 'message': 'El usuario no existe, verifique e intente nuevamente.'}), 404
        
        if user.status == 'suspended':
            return jsonify({'status': 'error', 'message': 'Tu cuenta ha sido suspendida, por favor comuniquese con el administrador del sitio'}), 401
        
        strikes = int(user.strikes) if user.strikes is not None else 0
        if  strikes >= 5:
            user.status = 'unverified'
            db.session.commit()
            return jsonify({'message': 'Tu cuenta ha sido suspendida debido a múltiples intentos fallidos'}), 401

        if check_password_hash(user.Password, password):
            user.strikes = 0
            db.session.commit()
            session['user'] = user.Email  # Almacena solo el email

            access_token = create_access_token(
                identity=str(user.CustomerID), 
                additional_claims=
                    {
                        'role': user.role, 
                        'username': email, 
                        'status': 'verified' if user.status == 'verified' else 'unverified', 
                        'id': user.CustomerID
                    }
                )
            
            session['current_token'] = access_token
            
            #create a new token in the Active_tokens table
                    
            # OBTENEMOS EL JTI DEL TOKEN RECIÉN CREADO
            access_jti = get_jti(access_token)
            
            # Creamos un nuevo registro en la tabla Active_tokens con el JTI
            newtoken = Active_tokens(CustomerID=user.CustomerID, jti=access_jti)
            db.session.add(newtoken)

            db.session.commit() 
            
            session['current_token'] = access_token
 
            return jsonify({'token': access_token, 'status': 'ok', 'role': user.role, 'username': user.Email}), 201
        else:
            strikes += 1
            user.strikes = strikes
            db.session.commit()
            attempts_left = 5 - user.strikes
            if user.strikes >= 5:
                return jsonify({'status': 'error', 'message': 'Tu cuenta ha sido suspendida por múltiples intentos fallidos.'}), 401
            else:
                return jsonify({'status': 'error', 'message': f'Contraseña incorrecta, te quedan {attempts_left} intentos.'}), 401
    except Exception as e:
        logging.error(f"Error en el login: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error interno. Intenta nuevamente.'}), 500

@backend.route('/register', methods=['POST'])
@roles_required(allowed_roles=["admin"])
def register():

    user_id = get_jwt().get("id")

    firstname = bleach.clean(request.json.get("firstname", ""), strip=True)
    lastname = bleach.clean(request.json.get("lastname", ""), strip=True)
    gender = bleach.clean(request.json.get("gender", ""), strip=True)

    password = request.json.get("password").strip()
    confirm_password = request.json.get("confirmPassword").strip()
    phone = request.json.get("phone").strip()
    countryCode = bleach.clean(request.json.get("countryCode", ""), strip=True)
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)
    birthday = request.json.get("Birthdate")
    role = request.json.get("role")
    eventAccess = request.json.get("eventAccess", [])  # Lista de IDs de eventos para acceso especial

    # Validación de datos de entrada
    if not (firstname and lastname and password and confirm_password and phone and email and birthday and gender and role):
        return jsonify(message='Faltan datos requeridos.'), 400
    
    if not utils.email_pattern.match(email):
        return jsonify(message='Dirección de correo electrónico no válida.'), 400
    
    if not utils.phone_pattern.match(phone):
        return jsonify(message='Número de teléfono no válido. Debe estar en formato E.164.'), 400

    if not utils.country_code_pattern.match(countryCode):
        return jsonify(message='Código de país no válido.'), 400
    
    if not signup_utils.system_strong_password_pattern.match(password):
        return jsonify(message='La contraseña no es lo suficientemente segura. Debe contener al menos una letra mayúscula, una minúscula, un número y un carácter especial, y tener una longitud mínima de 8 caracteres.'), 400

    if password != confirm_password:
        return jsonify(message='Las contraseñas no coinciden. Por favor, verifica.'), 400
    
    if gender not in ['Male', 'Female']:
        return jsonify(message='Selección de género no válida.'), 400
    
    if role not in ['admin', 'tiquetero', 'customer', 'passive_customer', 'provider', 'super_admin']:
        return jsonify(message='Selección de rol no válida.'), 400
    
    # Validación de fecha de nacimiento
    try:
        birthday = birthday.split("T")[0]
        birthday_date = datetime.strptime(birthday, '%Y-%m-%d')
        today = datetime.today()
        
        # Verificar que la fecha no sea futura
        if birthday_date > today:
            logging.error('La fecha de nacimiento no puede ser una fecha futura.')
            return jsonify({'message': 'La fecha de nacimiento no puede ser una fecha futura.'}), 400
        
        # Verificar que la edad no sea menor a 18 años
        age = (today - birthday_date).days // 365
        if age < 18:
            return jsonify({'message': 'Debes tener al menos 18 años para registrarte.'}), 400
        
        # Verificar que la edad no sea mayor a 150 años
        if age > 150:
            return jsonify(message='La edad máxima permitida es de 150 años. Por favor, verifica tu fecha de nacimiento.'), 400
    except ValueError:
        return jsonify(message='La fecha de nacimiento debe tener el formato AAAA-MM-DD.'), 400
    
    try:
        correo = db.session.query(EventsUsers).filter(and_(EventsUsers.Email == email)).one_or_none()

        if correo is not None:
            return jsonify(message='La dirección de correo electrónico ya existe.'), 409  # 409 Conflicto
        else:
            hashed_password = generate_password_hash(password)
            user = EventsUsers(
                Email=email,
                Password=hashed_password,
                FirstName=firstname,
                LastName=lastname,
                PhoneNumber=phone,
                birthday=birthday,
                status='unverified',
                role=role,
                Joindate=today,
                Gender=gender,
                CountryCode=countryCode
            )
            db.session.add(user)
            db.session.flush()  # Para obtener el CustomerID antes del commit

            if role == 'provider':

                event_access_ids = [int(event_id) for event_id in eventAccess if isinstance(event_id, int) or (isinstance(event_id, str) and event_id.isdigit())]
                events = db.session.query(Event).filter(Event.event_id.in_(event_access_ids)).all()

                if not events:
                    db.session.rollback()
                    return jsonify(message='No se encontraron eventos válidos para asignar al proveedor.'), 400
                
                if len(events) != len(event_access_ids):
                    db.session.rollback()
                    return jsonify(message='Algunos eventos proporcionados no son válidos.'), 400
                
                for event_id in event_access_ids:
                    association = EventUserAccess(event_id=event_id, user_id=user.CustomerID)
                    db.session.add(association)
                

            log_for_new_user = Logs(
                UserID=user_id,
                Type='nuevo usuario',
                Timestamp=datetime.now(),
                Details=f"Nuevo usuario registrado: {firstname} {lastname} ({email}) por admin ID-{user_id}",
            ) 
            db.session.add(log_for_new_user)

            # Aquí se puede agregar el código para enviar el correo de verificación
            signup_utils.validate_newuser(email, current_app.config, user)

            db.session.commit()
            
            response = make_response(jsonify({'status': 'ok'}))
            return response, 201
    except Exception as e:
        db.session.rollback()
        logging.error("Reversión de la transacción en la base de datos debido a un error.")
        logging.error(f"Ha ocurrido el siguiente error: {e}")
        return jsonify(message="Ocurrió un error inesperado. Por favor, intenta nuevamente más tarde."), 500
    
@backend.route('/edit-user-info', methods=['POST'])
@roles_required(allowed_roles=["admin"])
def edit_user_info():

    user_id = get_jwt().get("id")

    firstname = bleach.clean(request.json.get("firstname", ""), strip=True)
    lastname = bleach.clean(request.json.get("lastname", ""), strip=True)
    gender = bleach.clean(request.json.get("gender", ""), strip=True)
    customerId = request.json.get("customerId")
    password = request.json.get("password").strip()
    confirm_password = request.json.get("confirmPassword").strip()
    phone = request.json.get("phone").strip()
    countryCode = bleach.clean(request.json.get("countryCode", ""), strip=True)
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)
    birthday = request.json.get("Birthdate")
    role = request.json.get("role")
    modify_eventAccess = request.json.get("modifyEventAccess", False)

    # Validación de datos de entrada
    if not (firstname and lastname and phone and email and birthday and gender and role):
        return jsonify(message='Faltan datos requeridos.'), 400
    
    if not utils.email_pattern.match(email):
        return jsonify(message='Dirección de correo electrónico no válida.'), 400
    
    if not utils.phone_pattern.match(phone):
        return jsonify(message='Número de teléfono no válido. Debe estar en formato E.164.'), 400

    if not utils.country_code_pattern.match(countryCode):
        return jsonify(message='Código de país no válido.'), 400

    if gender not in ['Male', 'Female']:
        return jsonify(message='Selección de género no válida.'), 400
    
    if role not in ['admin', 'tiquetero', 'customer', 'passive_customer', 'provider', 'super_admin']:
        return jsonify(message='Selección de rol no válida.'), 400
    
    # Validación de fecha de nacimiento
    try:
        birthday = birthday.split("T")[0]
        birthday_date = datetime.strptime(birthday, '%Y-%m-%d')
        today = datetime.today()
        
        # Verificar que la fecha no sea futura
        if birthday_date > today:
            logging.error('La fecha de nacimiento no puede ser una fecha futura.')
            return jsonify({'message': 'La fecha de nacimiento no puede ser una fecha futura.'}), 400
        
        # Verificar que la edad no sea menor a 18 años
        age = (today - birthday_date).days // 365
        if age < 18:
            return jsonify({'message': 'Debes tener al menos 18 años para registrarte.'}), 400
        
        # Verificar que la edad no sea mayor a 150 años
        if age > 150:
            return jsonify(message='La edad máxima permitida es de 150 años. Por favor, verifica tu fecha de nacimiento.'), 400
    except ValueError:
        return jsonify(message='La fecha de nacimiento debe tener el formato AAAA-MM-DD.'), 400
    
    try:
        user = db.session.query(EventsUsers).filter(EventsUsers.CustomerID == int(customerId)).one_or_none()

        if user is None:
            return jsonify(message='El usuario no existe.'), 409  # 409 Conflicto
            
        if email != user.Email:
            correo = db.session.query(EventsUsers).filter(and_(EventsUsers.Email == email, EventsUsers.CustomerID != int(customerId))).one_or_none()

            if correo is not None:
                return jsonify(message='La dirección de correo electrónico ya existe.'), 409  # 409 Conflicto
            user.Email = email
            user.status = 'unverified'  # Reset status to unverified if email changes

            # Aquí se puede agregar el código para enviar el correo de verificación
            signup_utils.validate_newuser(email, current_app.config, user)
        
        if password:
            if not signup_utils.system_strong_password_pattern.match(password):
                return jsonify(message='La contraseña no es lo suficientemente segura. Debe contener al menos una letra mayúscula, una minúscula, un número y un carácter especial, y tener una longitud mínima de 8 caracteres.'), 400
            if not confirm_password:
                return jsonify(message='Debes confirmar la contraseña.'), 400
            if password != confirm_password:
                return jsonify(message='Las contraseñas no coinciden. Por favor, verifica.'), 400
            
            hashed_password = generate_password_hash(password)
            user.Password = hashed_password

        previous_role = user.role

        if previous_role == 'provider' and role != 'provider':
            # Si el rol cambia de provider a otro, eliminar todas las asociaciones de acceso a eventos
            db.session.query(EventUserAccess).filter(EventUserAccess.user_id == user.CustomerID).delete()
            db.session.flush()

        user.FirstName = firstname
        user.LastName = lastname
        user.PhoneNumber = phone
        user.CountryCode = countryCode
        user.birthday = birthday
        user.Gender = gender
        user.role = role

        if modify_eventAccess and role == 'provider':
            eventAccess = request.json.get("eventAccess", [])  # Lista de IDs de eventos para acceso especial
            event_access_ids = [int(event_id) for event_id in eventAccess if isinstance(event_id, int) or (isinstance(event_id, str) and event_id.isdigit())]
            
            # Primero, eliminamos las asociaciones existentes
            db.session.query(EventUserAccess).filter(EventUserAccess.user_id == user.CustomerID).delete()
            db.session.flush()

            if event_access_ids:
                events = db.session.query(Event).filter(Event.event_id.in_(event_access_ids)).all()

                if not events:
                    db.session.rollback()
                    return jsonify(message='No se encontraron eventos válidos para asignar al proveedor.'), 400
                
                if len(events) != len(event_access_ids):
                    db.session.rollback()
                    return jsonify(message='Algunos eventos proporcionados no son válidos.'), 400
                
                for event_id in event_access_ids:
                    association = EventUserAccess(event_id=event_id, user_id=user.CustomerID)
                    db.session.add(association)

        db.session.commit()

        log_for_edited_user = Logs(
            UserID=user_id,
            Type='usuario editado',
            Timestamp=datetime.now(),
            Details=f"usuario editado: {firstname} {lastname} ({email}) por admin ID-{user_id}",
        ) 
        db.session.add(log_for_edited_user)
        
        response = make_response(jsonify({'status': 'ok'}))
        return response, 201
    except Exception as e:
        db.session.rollback()
        logging.error("Reversión de la transacción en la base de datos debido a un error.")
        logging.error(f"Ha ocurrido el siguiente error: {e}")
        return jsonify(message="Ocurrió un error inesperado. Por favor, intenta nuevamente más tarde."), 500
    
@backend.route('/ban-user', methods=['POST'])
@roles_required(allowed_roles=["admin"])
def block_user():

    user_id = get_jwt().get("id")
    customerId = request.json.get("customerId")
    now_utc = datetime.now(timezone.utc)
    cutoff_date = now_utc + timedelta(days=30)
    
    try:
        user = db.session.query(EventsUsers).filter(EventsUsers.CustomerID == int(customerId)).one_or_none()

        if user is None:
            return jsonify(message='El usuario no existe.'), 409  # 409 Conflicto
        user.status = 'suspended'

        # eliminar el token activo del usuario (tokens que expiran en más de 30 días)
        active_tokens = db.session.query(Active_tokens).filter(and_(Active_tokens.CustomerID == user.CustomerID, Active_tokens.ExpiresAt > cutoff_date)).all()
        if active_tokens:
            for token in active_tokens:
                # Guardar el JTI en la base de datos
                revoked_token = Revoked_tokens(tokens=token.jti)
                db.session.add(revoked_token)

        log_for_edited_user = Logs(
            UserID=user_id,
            Type='usuario editado',
            Timestamp=datetime.now(),
            Details=f"usuario suspendido: ID-{user.CustomerID}/{user.Email} por admin ID-{user_id}",
        ) 
        db.session.add(log_for_edited_user)

        db.session.commit()

        utils.send_ban_notification(user.Email, current_app.config)
        
        response = make_response(jsonify({'status': 'ok'}))
        return response, 201
    except Exception as e:
        db.session.rollback()
        logging.error("Reversión de la transacción en la base de datos debido a un error.")
        logging.error(f"Ha ocurrido el siguiente error: {e}")
        return jsonify(message="Ocurrió un error inesperado. Por favor, intenta nuevamente más tarde."), 500
    
@backend.route('/logout', methods=['GET'])
@jwt_required()
def logout():
    try:
        # Decodificar el token actual para obtener el JTI
        decoded_token = get_jwt()  # Obtiene el payload del token
        token_jti = decoded_token["jti"]  # Extrae el identificador único del token

        # Guardar el JTI en la base de datos
        revoked_token = Revoked_tokens(tokens=token_jti)
        db.session.add(revoked_token)
        db.session.commit()
        
        return jsonify({'message': 'Su sesión ha finalizado', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error logging out: {e}")
        return jsonify({'message': 'Error logging out'}), 500
    
@backend.route('/load-dashboard', methods=['GET'])
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_dashboard():
    try:
        # Single query for total users and counts by role
        # NOTA: nullif(role != 'admin', True) cuenta admins porque:
        # - Si role != 'admin' es True (no es admin), devuelve NULL
        # - Si role != 'admin' es False (es admin), devuelve False
        # - COUNT solo cuenta valores no-NULL, por lo que cuenta cuando role == 'admin'
        total_users, total_admins, total_tiqueteros, total_customers, total_passive_customers = db.session.query(
            func.count(EventsUsers.CustomerID),
            func.count(func.nullif(EventsUsers.role != 'admin', True)),
            func.count(func.nullif(EventsUsers.role != 'tiquetero', True)),
            func.count(func.nullif(EventsUsers.role != 'customer', True)),
            func.count(func.nullif(EventsUsers.role != 'passive_customer', True)),
        ).one()

        sales = Sales.query.all()
        sales_data = []
        for sale in sales:
            sales_data.append({
                'sale_id': sale.sale_id,
                'fullname': sale.customer.FirstName if sale.customer else '',
                'status': sale.StatusFinanciamiento,
                'event': sale.event.name if sale.event else '',
                # BUG FIX: Corregido cálculo - precio final que paga el cliente (price - discount + fee)
                'price': round((sale.price - sale.discount + sale.fee)/100, 2),
                'saleLocator': sale.saleLocator,
                'user_email': sale.customer.Email if sale.customer else ''
            })

        dashboard_data = {
            'total_users': total_users,
            'total_admins': total_admins,
            'total_tiqueteros': total_tiqueteros,
            'total_customers': total_customers,
            'total_passive_customers': total_passive_customers,
        }



        return jsonify({
            'dashboard_data': dashboard_data,
            'sales_data': sales_data,
            'status': 'ok'
        }), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error loading dashboard data: {e}")
        return jsonify({'message': 'Error loading dashboard data', 'status': 'error'}), 500
    


ALLOWED_SEAT_EXTENSIONS = {'.csv', '.xls', '.xlsx'}
ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}

def allowed_file(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_SEAT_EXTENSIONS

def allowed_image(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_IMAGE_EXTENSIONS

@backend.route('/new-event', methods=['POST'])  # ruta para crear nuevos eventos
@roles_required(allowed_roles=["admin"])
def new_event():
    try:
        user_id = get_jwt().get("id")

        # EXTRACCION DE CAMPOS
        event_name = request.form.get('event')
        place = request.form.get('place')
        date = request.form.get('date')
        hour = request.form.get('hour')
        upload_method = request.form.get('uploadMethod')
        seat_file = request.files.get('seatFile')
        event_provider = request.form.get('externalProvider', None)
        event_id_provider = request.form.get('externalEvent', None)

        description = request.form.get('description', '')
        Type = request.form.get('Type', 'Espectaculo')
        active = request.form.get('active', '1') in ['1', 'true', 'True']
        Fee = request.form.get('Fee', None)
        duration = request.form.get('duration', None)
        clasification = request.form.get('clasification', None)
        age_restriction = request.form.get('age_restriction', None)

        main_image = request.files.get('mainImage')
        banner_image = request.files.get('bannerImage')
        banner_device = request.files.get('bannerImageDevice')

        # Validaciones básicas
        if not all([event_name, place, date, hour]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

        # Buscar o crear Venue
        venue = Venue.query.filter_by(name=place).first()
        if not venue:
            venue = Venue(name=place, address="No especificada", city="No especificada")
            db.session.add(venue)
            db.session.flush()

        # Guardar imágenes si hay
        main_path = None
        banner_path = None
        banner_dev_path = None

        S3_BUCKET = "imagenes-fiestatravel"
        if main_image and allowed_image(main_image.filename):
            key = f"events/{event_name.replace(' ', '_')}/{main_image.filename}"
            data = main_image.read()
            content_type = main_image.content_type
            main_path = utils_backend.upload_to_s3_public(s3, S3_BUCKET, key, data, content_type)
        if banner_image and allowed_image(banner_image.filename):
            key = f"events/{event_name.replace(' ', '_')}/{banner_image.filename}"
            data = banner_image.read()
            content_type = banner_image.content_type
            banner_path = utils_backend.upload_to_s3_public(s3, S3_BUCKET, key, data, content_type)
        if banner_device and allowed_image(banner_device.filename):
            key = f"events/{event_name.replace(' ', '_')}/{banner_device.filename}"
            data = banner_device.read()
            content_type = banner_device.content_type
            banner_dev_path = utils_backend.upload_to_s3_public(s3, S3_BUCKET, key, data, content_type)

        # Crear Event
        event_date = datetime.strptime(date, "%Y-%m-%d").date()
        event = Event(
            name=event_name,
            description=description,
            date=event_date,
            date_string=date,
            hour_string=hour,
            venue_id=venue.venue_id,
            Type=Type,
            mainImage=main_path,
            bannerImage=banner_path,
            bannerImageDevice=banner_dev_path,
            active=active,
            event_id_provider=int(event_id_provider) if event_id_provider else None,
            event_provider=int(event_provider) if event_provider else None,
            Fee=int(Fee) if Fee else None,
            duration=duration,
            clasification=clasification,
            age_restriction=age_restriction,
            created_by=user_id
        )
        db.session.add(event)
        db.session.flush()  # obtener event_id

        tickets_to_add = []

        # Procesamiento de asientos (archivo)
        if upload_method == 'file':
            if not seat_file:
                return jsonify({'message': 'Falta el archivo', 'status': 'error'}), 400
            if not allowed_file(seat_file.filename):
                return jsonify({'message': 'Formato de archivo no permitido', 'status': 'error'}), 400

            if seat_file.filename.lower().endswith('.csv'):
                df = pd.read_csv(seat_file)
            else:
                df = pd.read_excel(seat_file)

            df.columns = df.columns.str.strip().str.lower()
            required_cols = {'asiento', 'seccion', 'precio'}
            if not required_cols.issubset(df.columns):
                return jsonify({'message': 'El archivo no tiene las columnas requeridas', 'status': 'error'}), 400

            section_cache = {}
            seat_cache = {}
            for _, row in df.iterrows():
                asiento = str(row['asiento']).strip()
                seccion = str(row['seccion']).strip()
                precio = int(row['precio']) * 100

                section_key = (venue.venue_id, seccion)
                if section_key not in section_cache:
                    section = Section.query.filter_by(venue_id=venue.venue_id, name=seccion).first()
                    if not section:
                        section = Section(venue_id=venue.venue_id, name=seccion)
                        db.session.add(section)
                        db.session.flush()
                    section_cache[section_key] = section
                else:
                    section = section_cache[section_key]

                row_label = ''.join([ch for ch in asiento if ch.isalpha()])
                number = ''.join([ch for ch in asiento if ch.isdigit()])

                seat_key = (section.section_id, row_label, number)
                if seat_key not in seat_cache:
                    seat = Seat.query.filter_by(section_id=section.section_id, row=row_label, number=number).first()
                    if not seat:
                        seat = Seat(section_id=section.section_id, row=row_label, number=number)
                        db.session.add(seat)
                        db.session.flush()
                    seat_cache[seat_key] = seat
                else:
                    seat = seat_cache[seat_key]

                ticket = Ticket(
                    event_id=event.event_id,
                    ticket_id_provider=None,
                    seat_id=seat.seat_id,
                    price=precio,
                    status='disponible',
                    created_by=user_id
                )
                tickets_to_add.append(ticket)

        elif upload_method == 'from api':
            event_id = event_id_provider
            tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
            tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

            if not all([event_id]):
                return jsonify({"message": "Faltan parámetros: externalEvent"}, 400)

            event.event_id_provider = int(event_id) if event_id else None
            event.from_api = True

            # Llamada a servicio externo con retry
            url = f"{current_app.config.get('FIESTATRAVEL_API_URL')}/eventos_api/load-tickets"
            query = str(event.event_id_provider).strip()

            session = requests.Session()
            retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=frozenset(['GET', 'POST']))
            adapter = HTTPAdapter(max_retries=retries)
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            headers = {
                "Accept": "application/json",
                "User-Agent": "FiestaTickets/1.0",
                "X-Tickera-Id": tickera_id,
                "X-Tickera-Api-Key": tickera_api_key
            }
            params = {"query": query}
            verify = current_app.config.get("REQUESTS_VERIFY", 'True') == 'True'

            try:
                resp = session.get(url, params=params, headers=headers, timeout=(5, 60), verify=verify)
                resp.raise_for_status()
                data = resp.json()
                tickets = data.get("tickets", [])
            except requests.exceptions.RequestException:
                logging.exception("Error al comunicarse con proveedor externo")
                raise
            finally:
                try:
                    session.close()
                except Exception:
                    pass

            section_cache = {}
            seat_cache = {}
            for ticket_data in tickets:
                asiento = str(ticket_data.get('seat', '')).strip()
                seccion = str(ticket_data.get('section', '')).strip()
                precio = int(ticket_data.get('price', 0))
                ticket_id_fromprovider = int(ticket_data.get('ticket_id_provider', 0))

                if not all([asiento, seccion, precio, ticket_id_fromprovider]):
                    return jsonify({'message': 'Datos incompletos en tickets desde API', 'status': 'error'}), 400

                section_key = (venue.venue_id, seccion)
                if section_key not in section_cache:
                    section = Section.query.filter_by(venue_id=venue.venue_id, name=seccion).first()
                    if not section:
                        section = Section(venue_id=venue.venue_id, name=seccion)
                        db.session.add(section)
                        db.session.flush()
                    section_cache[section_key] = section
                else:
                    section = section_cache[section_key]

                row_label = ''.join([ch for ch in asiento if ch.isalpha()])
                number = ''.join([ch for ch in asiento if ch.isdigit()])

                seat_key = (section.section_id, row_label, number)
                if seat_key not in seat_cache:
                    seat = Seat.query.filter_by(section_id=section.section_id, row=row_label, number=number).first()
                    if not seat:
                        seat = Seat(section_id=section.section_id, row=row_label, number=number)
                        db.session.add(seat)
                        db.session.flush()
                    seat_cache[seat_key] = seat
                else:
                    seat = seat_cache[seat_key]

                ticket = Ticket(
                    event_id=event.event_id,
                    ticket_id_provider=ticket_id_fromprovider,
                    seat_id=seat.seat_id,
                    price=precio,
                    status='disponible',
                    created_by=user_id
                )
                tickets_to_add.append(ticket)
        # Insert all tickets
        if tickets_to_add:
            db.session.add_all(tickets_to_add)

        db.session.commit()
        return jsonify({'message': 'Evento y tickets creados exitosamente', 'status': 'ok'}), 200

    except requests.exceptions.RequestException as e:
        db.session.rollback()
        return jsonify({"message": f"Error en el request externo: {str(e)}"}), 500
    except Exception as e:
        db.session.rollback()
        logging.exception("Error al crear evento")
        return jsonify({'message': 'Error al crear evento', 'status': 'error', 'detail': str(e)}), 500


@backend.route('/update-event', methods=['POST'])  # ruta para editar eventos existentes
@roles_required(allowed_roles=["admin"])
def update_event():
    """
    Actualiza un evento existente. Si se entrega un nuevo seatFile o uploadMethod distinto,
    se reemplazan los tickets asociados al evento (se eliminan los previos y se insertan los nuevos).
    """
    try:
        event_id = request.args.get('eventId')
        # Validar que event_id sea un entero válido
        if not event_id:
            return jsonify({'message': 'Falta el parámetro eventId', 'status': 'error'}), 400
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            return jsonify({'message': 'ID de evento inválido', 'status': 'error'}), 400
        
        event = Event.query.filter_by(event_id=event_id).first()
        if not event:
            return jsonify({'message': 'Evento no encontrado', 'status': 'error'}), 404

        # Extracción de campos (mismos nombres que new-event)
        event_name = request.form.get('event')
        place = request.form.get('place')
        date = request.form.get('date')
        hour = request.form.get('hour')
        event_provider = request.form.get('externalProvider', None)
        event_id_provider = request.form.get('externalEvent', None)

        description = request.form.get('description', event.description)
        Type = request.form.get('Type', event.Type or 'Espectaculo')
        active = request.form.get('active', '1') in ['1', 'true', 'True']
        Fee = request.form.get('Fee', event.Fee)
        duration = request.form.get('duration', event.duration)
        clasification = request.form.get('clasification', event.clasification)
        age_restriction = request.form.get('age_restriction', event.age_restriction)

        main_image = request.files.get('mainImage')
        banner_image = request.files.get('bannerImage')
        banner_device = request.files.get('bannerImageDevice')

        # Actualizar campos simples
        if event_name:
            event.name = event_name
        if date:
            event.date = datetime.strptime(date, "%Y-%m-%d").date()
            event.date_string = date
        if hour:
            event.hour_string = hour
        event.description = description
        event.Type = Type
        event.active = active
        event.Fee = int(Fee) if Fee else None
        event.duration = duration
        event.clasification = clasification
        event.age_restriction = age_restriction
        event.event_provider = int(event_provider) if event_provider else None
        event.event_id_provider = int(event_id_provider) if event_id_provider else None

        # Venue update / creation
        if place:
            venue = Venue.query.filter_by(name=place).first()
            if not venue:
                venue = Venue(name=place, address="No especificada", city="No especificada")
                db.session.add(venue)
                db.session.flush()
            event.venue_id = venue.venue_id

        S3_BUCKET = "imagenes-fiestatravel"

        # Guardar imágenes si vienen
        if main_image and allowed_image(main_image.filename):
            key = f"events/{event_name.replace(' ', '_')}/{main_image.filename}"
            data = main_image.read()
            content_type = main_image.content_type
            event.mainImage = utils_backend.upload_to_s3_public(s3, S3_BUCKET, key, data, content_type)
        if banner_image and allowed_image(banner_image.filename):
            key = f"events/{event_name.replace(' ', '_')}/{banner_image.filename}"
            data = banner_image.read()
            content_type = banner_image.content_type
            event.bannerImage = utils_backend.upload_to_s3_public(s3, S3_BUCKET, key, data, content_type)
        if banner_device and allowed_image(banner_device.filename):
            key = f"events/{event_name.replace(' ', '_')}/{banner_device.filename}"
            data = banner_device.read()
            content_type = banner_device.content_type
            event.bannerImageDevice = utils_backend.upload_to_s3_public(s3, S3_BUCKET, key, data, content_type)

        db.session.commit()
        return jsonify({'message': 'Evento actualizado correctamente', 'status': 'ok'}), 200

    except requests.exceptions.RequestException as e:
        db.session.rollback()
        return jsonify({"message": f"Error en el request externo: {str(e)}"}), 500
    except Exception as e:
        db.session.rollback()
        logging.exception("Error al actualizar evento")
        return jsonify({'message': 'Error al actualizar evento', 'status': 'error', 'detail': str(e)}), 500


@backend.route('/load-events', methods=['GET'])  # ver eventos creados
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_events():
    """
    Devuelve:
      - events: lista plana con cada registro de Event y todos sus campos relevantes (venue embebido, provider embebido,
                imágenes, tipo, tarifas, duración, clasificación, restricción de edad, conteo de tickets, etc.)
      - unique_events: lista agrupada por nombre de evento, cada entrada contiene "name" y "venues" (lista de venues disponibles para ese nombre)
      - providers: lista de proveedores disponibles
      - status: 'ok' | 'error'
    El endpoint intenta ser tolerante a diferencias de nombres de modelos (Provider vs Providers).
    """
    try:
        # Cargar todos los eventos (puedes optimizar con joinedload si lo deseas)
        events = Event.query.order_by(Event.date.asc(), Event.hour_string.asc()).all()

        # Cargar proveedores si el modelo existe
        providers = Providers.query.all() if Providers is not None else []

        events_list = []
        # Para evitar consultas repetidas, cache de venues por venue_id
        venue_cache = {}

        for ev in events:
            # Resolver venue (puede venir por relationship o por FK)
            venue_obj = None
            try:
                # intentar acceso por relación 
                venue_obj = ev.venue if hasattr(ev, "venue") else None
            except Exception:
                venue_obj = None

            if not venue_obj and getattr(ev, "venue_id", None) is not None:
                vid = ev.venue_id
                if vid in venue_cache:
                    venue_obj = venue_cache[vid]
                else:
                    venue_obj = Venue.query.filter_by(venue_id=vid).first()
                    venue_cache[vid] = venue_obj

            venue_payload = None
            if venue_obj:
                venue_payload = {
                    "venue_id": getattr(venue_obj, "venue_id", None),
                    "name": getattr(venue_obj, "name", None),
                    "address": getattr(venue_obj, "address", None),
                    "city": getattr(venue_obj, "city", None)
                }

            # Resolver proveedor embebido si existe la relación o FK
            provider_payload = None
            provider_id_field = getattr(ev, "event_provider", None)
            if provider_id_field:
                try:
                    if Providers is not None:
                        provider_obj = Providers.query.filter_by(ProviderID=provider_id_field).first()
                        if provider_obj:
                            provider_payload = {
                                "ProviderID": getattr(provider_obj, "ProviderID", None),
                                "ProviderName": getattr(provider_obj, "ProviderName", None),
                            }
                except Exception:
                    # no romper si la consulta falla, dejar provider_payload como None
                    provider_payload = None

            events_list.append({
                "event_id": getattr(ev, "event_id", None),
                "name": getattr(ev, "name", None),
                "description": getattr(ev, "description", None),
                "date": getattr(ev, "date").isoformat() if getattr(ev, "date", None) else None,
                "date_string": getattr(ev, "date_string", None),
                "hour_string": getattr(ev, "hour_string", None),
                "venue": venue_payload,
                # lista de todos los venues que comparten el mismo nombre se calculará más abajo en unique_events
                "Type": getattr(ev, "Type", None),
                "mainImage": getattr(ev, "mainImage", None),
                "bannerImage": getattr(ev, "bannerImage", None),
                "bannerImageDevice": getattr(ev, "bannerImageDevice", None),
                "active": bool(getattr(ev, "active", True)),
                "event_id_provider": getattr(ev, "event_id_provider", None),
                "event_provider": getattr(ev, "event_provider", None),
                "Fee": getattr(ev, "Fee", None),
                "duration": getattr(ev, "duration", None),
                "clasification": getattr(ev, "clasification", None),
                "age_restriction": getattr(ev, "age_restriction", None),
                "created_by": getattr(ev, "created_by", None),
                "created_at": getattr(ev, "created_at").isoformat() if getattr(ev, "created_at", None) else None,
            })

        # Construir lista de proveedores con shape esperado por frontend
        providers_list = []
        for p in providers:
            providers_list.append({
                "ProviderID": getattr(p, "ProviderID", None),
                "ProviderName": getattr(p, "ProviderName", None),
            })

        # Construir unique_events agrupado por nombre de evento, con lista de venues (sin duplicados)
        unique_events_map = {}
        for ev in events_list:
            name = ev.get("name") or "Sin nombre"
            if name not in unique_events_map:
                unique_events_map[name] = {"name": name, "venues": []}

            # Evitar duplicar venues en la misma entrada
            v = ev.get("venue")
            if v:
                existing_ids = {ven["venue_id"] for ven in unique_events_map[name]["venues"] if ven.get("venue_id") is not None}
                if v.get("venue_id") not in existing_ids:
                    unique_events_map[name]["venues"].append(v)

        # Eliminar duplicados por event_id en la lista principal (por si acaso)
        all_events = {e["event_id"]: e for e in events_list if e.get("event_id") is not None}
        # si hay eventos sin event_id, los añadimos igualmente con claves incrementales para preservarlos
        missing_id_events = [e for e in events_list if e.get("event_id") is None]
        for i, e in enumerate(missing_id_events, start=1):
            all_events[f"noid-{i}"] = e

        return jsonify({
            "events": list(all_events.values()),
            "unique_events": list(unique_events_map.values()),
            "providers": providers_list,
            "status": "ok"
        }), 200

    except Exception as e:
        # rollback en caso de haber modificado la sesión
        try:
            db.session.rollback()
        except Exception:
            pass
        logging.exception("Error al cargar eventos")
        return jsonify({'message': 'Error al cargar eventos', 'status': 'error', 'detail': str(e)}), 500
    
@backend.route('/load-sales', methods=['GET']) #ver ventas en general
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_sales():
    try:

        from_date_str = request.args.get('from_date', '')
        statuses_str = request.args.get('status', '')
        until_date_str = request.args.get('until_date', '')
        events_str = request.args.get('events', '')

        if not from_date_str and not statuses_str:
            return jsonify({'message': 'Se requiere al menos un filtro (from_date o status)', 'status': 'error'}), 400
    
        # Usamos joinedload para evitar N+1 queries
        events = Event.query.options(
            joinedload(Event.venue).load_only(
                Venue.venue_id, Venue.name, Venue.address, Venue.city
            ),
            load_only(Event.event_id, Event.name, Event.description, Event.date, Event.date_string, Event.hour_string, Event.venue_id, Event.active)
        ).all()

        events_dict = {}
        all_events = []
        for event in events:

            all_events.append({
                'event_id': event.event_id,
                'event': event.name,
                'venue': event.venue.name if event.venue else None,
                'event_date': event.date_string,
                'event_hour': event.hour_string,
            })

            if event.active == True: # Solo agregamos eventos activos
                if event.name not in events_dict:
                    events_dict[event.name] = {
                        "event_id": event.event_id,
                        "name": event.name,
                        "description": event.description,
                        "venues": [],
                    }

                # Buscamos si el venue ya está agregado para este evento
                existing_venue = next((v for v in events_dict[event.name]["venues"]
                                    if v["venue_id"] == event.venue.venue_id), None)
                if existing_venue:
                    existing_venue["dates"].append({
                        "date": event.date.isoformat(),
                        "hour": event.hour_string
                    })
                else:
                    events_dict[event.name]["venues"].append({
                        "venue_id": event.venue.venue_id,
                        "name": event.venue.name,
                        "address": event.venue.address,
                        "city": event.venue.city,
                        "dates": [{
                            "date": event.date_string,
                            "hour": event.hour_string
                        }]
                    })

        # Parse from_date as a datetime object if provided
        from_date = None
        until_date = None

        
        if from_date_str:
            from_date_str = from_date_str.split('T')[0]  # Extraer solo la parte de la fecha
            try:
                from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
            except ValueError:
                return jsonify({'message': 'Formato de fecha inválido. Usa YYYY-MM-DD.', 'status': 'error'}), 400
            
        if until_date_str:
            until_date_str = until_date_str.split('T')[0]  # Extraer solo la parte de la fecha
            try:
                until_date = datetime.strptime(until_date_str, '%Y-%m-%d')
            except ValueError:
                return jsonify({'message': 'Formato de fecha inválido. Usa YYYY-MM-DD.', 'status': 'error'}), 400

        events = events_str.split(',') if events_str else []

        statuses = statuses_str.split(',') if statuses_str else []

        # Información de ventas
        query = Sales.query.options(
            joinedload(Sales.customer).load_only(EventsUsers.FirstName, EventsUsers.LastName, EventsUsers.Email),
            joinedload(Sales.event_rel).load_only(Event.name),
            load_only(Sales.sale_id, Sales.event, Sales.status, Sales.price, Sales.discount, Sales.fee, Sales.saleLocator, Sales.saleLink, Sales.creation_date)
        )

        filters = []
        filters_stats = []
        if from_date:
            from_date = from_date.date()  # asegúrate de tener un date
            filters.append(Sales.creation_date >= from_date)
            filters_stats.append(Sales.creation_date >= from_date)
        if until_date_str:
            until_date = until_date.date()  # asegúrate de tener un date
            filters.append(Sales.creation_date <= until_date)
            filters_stats.append(Sales.creation_date <= until_date)
        if events and any(events):
            filters.append(Sales.event.in_(events))
            filters_stats.append(Sales.event.in_(events))
        if statuses and any(statuses):
            filters.append(Sales.status.in_(statuses))

        if filters:
            query = query.filter(and_(*filters))

        sales = query.all()

        sales_data = []
        for sale in sales:
            sales_data.append({
                'sale_id': sale.sale_id,
                'firstname': sale.customer.FirstName if sale.customer else '',
                'lastname': sale.customer.LastName if sale.customer else '',
                'status': sale.status,
                'event': sale.event_rel.name if sale.event else '',
                'price': round((sale.price - sale.discount + sale.fee )/100, 2),
                'saleLocator': sale.saleLocator,
                'saleLink': sale.saleLink,
                'email': sale.customer.Email if sale.customer else '',
                'saleDate': sale.creation_date.isoformat() if sale.creation_date else ''
            })

        sales_data = sorted(sales_data, key=lambda x: x['saleDate'], reverse=True)

        # Cálculo de totales
        sales_info = {}

        # Usar CASE con IN para los estados "pendientes" y asegurar valores por defecto
        sums_query = (
            db.session.query(
                # total de ventas pagadas
                func.coalesce(func.sum(case((Sales.status == 'pagado', 1), else_=0)), 0).label('total_paid_sales'),
                # total de ventas en estados pendientes (una sola CASE con IN)
                func.coalesce(func.sum(case((Sales.status.in_(['pagado por verificar', 'pendiente pago']), 1), else_=0)), 0).label('total_pending_sales'),
            )
            .select_from(Sales)
            .filter(
                and_(*filters_stats),
            )
        )

        # one_or_none normalmente devuelve una fila con agregados; proteger contra None por seguridad
        agg = sums_query.one_or_none() or type('AGG', (), {'total_paid_sales': 0, 'total_pending_sales': 0})()

        total_paid_sales = int(agg.total_paid_sales or 0)
        total_pending_sales = int(agg.total_pending_sales or 0)

        sales_info['total_paid_sales'] = total_paid_sales
        sales_info['total_pending_sales'] = total_pending_sales

        #por ultimo, recopilamos loa lista de cupones aplicables
        discounts = Discounts.query.filter(Discounts.Active == True, Discounts.ApplicableUsers == None).all()
        discounts_list = []

        if discounts:
            for discount in discounts:
                discounts_list.append({
                    'discount_id': discount.DiscountID,
                    'code': discount.Code,
                    'description': discount.Description,
                    'fixed_amount': discount.FixedAmount if discount.FixedAmount else 0,
                    'percentage': discount.Percentage if discount.Percentage else 0,
                    'aplicable_events': discount.ApplicableEvents,
                })

        return jsonify({"unique_events": list(events_dict.values()), "events": all_events, "sales": sales_data, "status": "ok", "dashboard_data": sales_info, "coupons": discounts_list}), 200


    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear evento: {e}")
        return jsonify({'message': 'Error al crear evento', 'status': 'error'}), 500
    
@backend.route('/load-successful-sales', methods=['GET']) #ver paquetes o ventas en general
@roles_required(allowed_roles=["admin"])
def load_successful_sales():
    try:

        from_date_str = request.args.get('from_date', '')
        until_date_str = request.args.get('until_date', '')
        events_str = request.args.get('events', '')

        from_date = None
        until_date = None
        
        if from_date_str:
            from_date_str = from_date_str.split('T')[0]  # Extraer solo la parte de la fecha
            try:
                from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
            except ValueError:
                return jsonify({'message': 'Formato de fecha inválido. Usa YYYY-MM-DD.', 'status': 'error'}), 400
        if until_date_str:
            until_date_str = until_date_str.split('T')[0]  # Extraer solo la parte de la fecha
            try:
                until_date = datetime.strptime(until_date_str, '%Y-%m-%d')
            except ValueError:
                return jsonify({'message': 'Formato de fecha inválido. Usa YYYY-MM-DD.', 'status': 'error'}), 400

        events = events_str.split(',') if events_str else []

        # Información de ventas
        query = Sales.query.options(
            joinedload(Sales.customer).load_only(EventsUsers.FirstName, EventsUsers.LastName, EventsUsers.Email),
            joinedload(Sales.event_rel).load_only(Event.name, Event.event_id),
            load_only(Sales.sale_id, Sales.status, Sales.price, Sales.discount, Sales.fee, Sales.saleLocator, Sales.saleLink, Sales.creation_date, Sales.liquidado)
        )

        filters = []
        if from_date:
            from_date = from_date.date()  # asegúrate de tener un date
            filters.append(Sales.creation_date >= from_date)
        if until_date_str:
            until_date = until_date.date()  # asegúrate de tener un date
            filters.append(Sales.creation_date <= until_date)
        if events and any(events):
            filters.append(Sales.event.in_(events))

        filters.append(Sales.status=='pagado')

        if filters:
            query = query.filter(and_(*filters))

        sales = query.all()

        sales_data = []
        for sale in sales:
            sales_data.append({
                'sale_id': sale.sale_id,
                'firstname': sale.customer.FirstName if sale.customer else '',
                'lastname': sale.customer.LastName if sale.customer else '',
                'status': sale.status,
                'event': sale.event_rel.name if sale.event_rel else '',
                'event_date': sale.event_rel.date_string if sale.event_rel else '',
                'event_place': sale.event_rel.venue.name if sale.event_rel else '',
                'event_hour': sale.event_rel.hour_string if sale.event_rel else '',
                'event_id': sale.event_rel.event_id if sale.event_rel else '',
                'price': round((sale.price - sale.discount + sale.fee )/100, 2),
                'fee': round(sale.fee/100, 2),
                'saleLocator': sale.saleLocator,
                'saleLink': sale.saleLink,
                'email': sale.customer.Email if sale.customer else '',
                'saleDate': sale.creation_date.isoformat() if sale.creation_date else '',
                'liquidado': sale.liquidado
            })

        all_events = Event.query.options(
            joinedload(Event.venue).load_only(Venue.venue_id, Venue.name),
            load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string, Event.venue_id)
        ).all()
        events_list = []
        for event in all_events:
            events_list.append({
                "event_id": event.event_id,
                "event": event.name,
                "event_date": event.date_string,
                "event_hour": event.hour_string,
                "event_place": event.venue.name
            })

        sales_data = sorted(sales_data, key=lambda x: x['saleDate'], reverse=True)

        return jsonify({"sales": sales_data, "status": "ok", "events": events_list}), 200


    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear evento: {e}")
        return jsonify({'message': 'Error al crear evento', 'status': 'error'}), 500
    
@backend.route('/create-liquidation', methods=['GET']) #ver paquetes o ventas en general
@roles_required(allowed_roles=["admin"])
def create_liquidation():
    try:

        event = request.args.get('id_event', '')

        if not event:
            return jsonify({'message': 'faltan parámetros', 'status': 'error'}), 400
        
        # Validar que event sea un entero válido
        try:
            event = int(event)
        except (TypeError, ValueError):
            return jsonify({'message': 'ID de evento inválido', 'status': 'error'}), 400

        # Información de ventas
        query = Sales.query.options(
            joinedload(Sales.customer).load_only(EventsUsers.Email),
            # Eager-load tickets and their related seat and section to avoid N+1 and ensure attributes are available
            joinedload(Sales.tickets).load_only(Ticket.ticket_id, Ticket.seat_id, Ticket.price)
                .joinedload(Ticket.seat).load_only(Seat.section_id, Seat.row, Seat.number)
                .joinedload(Seat.section).load_only(Section.section_id, Section.name),
            joinedload(Sales.payment).load_only(Payments.PaymentMethod),
            joinedload(Sales.event_rel).load_only(Event.name, Event.event_id, Event.date_string, Event.hour_string, Event.venue_id, Event.liquidado, Event.total_sales, Event.gross_sales, Event.total_fees)
                .joinedload(Event.provider).load_only(Providers.ProviderID, Providers.ProviderName),
            load_only(Sales.sale_id, Sales.price, Sales.discount, Sales.fee, Sales.saleLink, Sales.creation_date, Sales.liquidado)
        )

        filters = []

        filters.append(Sales.status=='pagado')
        filters.append(Sales.event==event)
        filters.append(Sales.liquidado==False)

        if filters:
            query = query.filter(and_(*filters))

        sales = query.all()
        sales_data = []

        if sales:

            print (sales[0].event_rel)

            event_info = {
                "event_id": sales[0].event_rel.event_id if sales[0].event_rel else '',
                "provider_name": sales[0].event_rel.provider.ProviderName if (sales[0].event_rel and sales[0].event_rel.provider) else '',
                "event": sales[0].event_rel.name,
                "event_date": sales[0].event_rel.date_string,
                "event_hour": sales[0].event_rel.hour_string,
                "event_place": sales[0].event_rel.venue.name,
                "total_liquidated": round((getattr(sales[0].event_rel, 'liquidado', 0) or 0)/100, 2),
                "total_sales": getattr(sales[0].event_rel, 'total_sales', 0) or 0,
                "gross_sales": round((getattr(sales[0].event_rel, 'gross_sales', 0) or 0)/100, 2),
                "total_fees": round((getattr(sales[0].event_rel, 'total_fees', 0) or 0)/100, 2)
            }

            for sale in sales:
                sales_data.append({
                    'sale_id': sale.sale_id,
                    'firstname': sale.customer.FirstName if sale.customer else '',
                    'lastname': sale.customer.LastName if sale.customer else '',
                    'price': round((sale.price - sale.discount + sale.fee )/100, 2),
                    'saleLink': sale.saleLink,
                    'email': sale.customer.Email if sale.customer else '',
                    'saleDate': sale.creation_date.isoformat() if sale.creation_date else '',
                    'liquidado': sale.liquidado,
                    'tickets': [{
                        'ticket_id': ticket.ticket_id,
                        'sale_id': sale.sale_id,
                        'price': round(ticket.price/100, 2),
                        'section': ticket.seat.section.name if ticket.seat and ticket.seat.section else '',
                        'row': ticket.seat.row if ticket.seat else '',
                        'number': ticket.seat.number if ticket.seat else '',
                        'dateofPurchase': ticket.emission_date.isoformat() if ticket.emission_date else ''
                    } for ticket in sale.tickets],
                    'paymentsMethod': sale.payment.PaymentMethod if sale.payment else ''
                })

        else:
            event_obj = Event.query.options(
                load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string, Event.venue_id, Event.liquidado, Event.total_sales, Event.gross_sales, Event.total_fees),
                joinedload(Event.provider).load_only(Providers.ProviderID, Providers.ProviderName),
                joinedload(Event.venue).load_only(Venue.venue_id, Venue.name)
            ).filter(Event.event_id == event).one_or_none()

            if not event_obj:
                return jsonify({"message": "No se encontró el evento"}), 404
            
            event_info = {
                "event_id": event_obj.event_id,
                "provider_name": event_obj.provider.ProviderName if (event_obj.provider) else '',
                "event": event_obj.name,
                "event_date": event_obj.date_string,
                "event_hour": event_obj.hour_string,
                "event_place": event_obj.venue.name if event_obj.venue else '',
                "total_liquidated": round((getattr(event_obj, 'liquidado', 0) or 0)/100, 2),
                "total_sales": getattr(event_obj, 'total_sales', 0) or 0,
                "gross_sales": round((getattr(event_obj, 'gross_sales', 0) or 0)/100, 2),
                "total_fees": round((getattr(event_obj, 'total_fees', 0) or 0)/100, 2)
                }



        sales_data = sorted(sales_data, key=lambda x: x['saleDate'], reverse=True)

        return jsonify({"sales": sales_data, "status": "ok", "event": event_info}), 200


    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear evento: {e}")
        return jsonify({'message': 'Error al crear evento', 'status': 'error'}), 500
    
@backend.route('/create-liquidation', methods=['POST']) #ver paquetes o ventas en general
@roles_required(allowed_roles=["admin"])
def create_liquidation_post():
    try:
        data = request.get_json()
        event_str = data.get('event_id', '')
        seats = data.get('seats', [])
        sections = data.get('sections', [])
        totals = data.get('totals', {})
        additionalCharges = data.get('additionalCharges', {})
        discounts = data.get('discounts', {})
        payment = data.get('payment', {})
        comments = data.get('comments', '')

        if not event_str or not seats or not sections or not totals or not payment:
            return jsonify({'message': 'faltan parámetros', 'status': 'error'}), 400
        
        sales_list = [int(seats_item.get('sale_id')) for seats_item in seats if seats_item.get('sale_id')]
        #eliminar duplicados
        sales_list = list(set(sales_list))  
        
        sales = Sales.query.options(
            joinedload(Sales.customer).load_only(EventsUsers.Email),
            # Eager-load tickets and their related seat and section to avoid N+1 and ensure attributes are available
            joinedload(Sales.tickets).load_only(Ticket.ticket_id, Ticket.seat_id, Ticket.price)
                .joinedload(Ticket.seat).load_only(Seat.section_id, Seat.row, Seat.number)
                .joinedload(Seat.section).load_only(Section.section_id, Section.name),
            joinedload(Sales.payment).load_only(Payments.PaymentMethod),
            joinedload(Sales.event_rel).load_only(Event.name, Event.event_id)
                .joinedload(Event.provider).load_only(Providers.ProviderID, Providers.ProviderName, Providers.ProviderEmail),
            load_only(Sales.sale_id, Sales.price, Sales.discount, Sales.fee, Sales.saleLink, Sales.creation_date, Sales.liquidado)
        ).filter(
            and_(
                Sales.sale_id.in_(sales_list),
                Sales.status=='pagado',
                Sales.event==int(event_str),
                Sales.liquidado!=True
            )
        ).all() 

        if not sales:
            return jsonify({'message': 'No se encontraron ventas válidas para liquidar', 'status': 'error'}), 400

        if len(sales) != len(sales_list):
            return jsonify({'message': 'Algunas ventas no se encontraron o ya están liquidadas', 'status': 'error'}), 400

        total_liquidation = totals.get('totalFinal', 0)
        discounts_string = totals.get('totalDiscounts', 0)
        # Crear string additionalCharges en formato "name,price||name,price||..."
        if isinstance(additionalCharges, list):
            additional_charges_string = "||".join(
            f"{str(item.get('name','')).strip()},{int(item.get('price', 0))}"
            for item in additionalCharges
            if item and item.get('name') is not None
            )
        else:
            additional_charges_string = ""

        # Crear string additionalCharges en formato "name,price||name,price||..."
        if isinstance(discounts, list):
            discounts_string = "||".join(
            f"{str(item.get('name','')).strip()},{int(item.get('price', 0))}"
            for item in discounts
            if item and item.get('name') is not None
            )
        else:
            discounts_string = ""

        # Normalizar totales usados más abajo

        event_provider = sales[0].event_rel.provider.ProviderID if (sales[0].event_rel and sales[0].event_rel.provider) else None
        
        liquidation = Liquidations(
            EventID=int(event_str),
            Amount=total_liquidation*100,
            AmountBS=payment.get('amountBolivares', 0)*100,
            LiquidationDate=payment.get('date'),
            CreatedBy=get_jwt().get("id"),
            ProviderID=int(event_provider) if event_provider else None,
            PaymentMethod=payment.get('method', ''),   
            Reference=payment.get('reference', ''),
            Discount=discounts_string,
            AdditionalFees=additional_charges_string,
            Comments=comments
        )
        db.session.add(liquidation)
        db.session.flush()  # para obtener liquidation_id

        sales_total = 0
        for sale in sales:
            sale.liquidado = True
            sale.liquidation_id = liquidation.LiquidationID
            sales_total += (sale.price)

        liquidated_amount_net = totals.get('totalGlobal', 0)*100 # convertir a centavos, el total correspondiente a los boletos vendidos

        if sales_total != liquidated_amount_net:
            return jsonify({'message': 'Los totales no coinciden', 'status': 'error'}), 400

        event = sales[0].event_rel

        if event.liquidado:
            event.liquidado += liquidated_amount_net 
        else: event.liquidado = liquidated_amount_net

        # -------------------------
        # Generar PDF en memoria
        # -------------------------
        try:
            def format_currency(value, symbol="$", decimals=2):
                """
                Formatea un número como moneda: por ejemplo 1234.5 -> $1,234.50
                Uso en Jinja: {{ value | currency }}
                """
                try:
                    v = float(value or 0)
                except Exception:
                    # si no es convertible, devolver como string
                    return str(value)
                # separador de miles con coma y punto decimal
                return f"{symbol}{v:,.{decimals}f}"
            def format_currency_bsD(value, symbol="BsD", decimals=2):
                """
                Formatea un número como moneda: por ejemplo 1234.5 -> BsD1,234.50
                Uso en Jinja: {{ value | currency_Bsd }}
                """
                try:
                    v = float(value or 0)
                except Exception:
                    # si no es convertible, devolver como string
                    return str(value)
                # separador de miles con coma y punto decimal
                return f"{symbol}{v:,.{decimals}f}"
            def format_currency_cents_to_dollars(value, symbol="$", decimals=2):
                """
                Formatea un número como moneda: por ejemplo 123450 -> $1,234.50
                Uso en Jinja: {{ value | currency }}
                """
                try:
                    v = float(value/100 or 0)
                except Exception:
                    # si no es convertible, devolver como string
                    return str(value/100)
                # separador de miles con coma y punto decimal
                return f"{symbol}{v:,.{decimals}f}"

            current_app.jinja_env.filters['currency'] = format_currency
            current_app.jinja_env.filters['currency_Bsd'] = format_currency_bsD
            current_app.jinja_env.filters['currency_cents_to_dollars'] = format_currency_cents_to_dollars
            pdf_bytes = utils_backend.generate_pdf_with_weasyprint(liquidation, event, sales, totals, discounts, additionalCharges, payment, comments, sections)
        except Exception as e:
            logging.error(f"Error generando PDF de liquidación: {e}")
            return jsonify({'message': 'Error generando PDF', 'status': 'error'}), 500

        # -------------------------
        # Subir a S3
        # -------------------------
        S3_BUCKET = "imagenes-fiestatravel"
        if not S3_BUCKET:
            logging.error("No se configuró S3_BUCKET")
            return jsonify({'message': 'Configuración de almacenamiento no encontrada', 'status': 'error'}), 500

        s3_key = f"liquidations/{liquidation.LiquidationID}.pdf"
        uploaded = utils_backend.upload_to_s3_private(s3, S3_BUCKET, s3_key, pdf_bytes, content_type='application/pdf')
        if not uploaded:
            # No hacemos rollback porque la DB fue commiteada, pero informamos
            return jsonify({'message': 'Error subiendo PDF a almacenamiento', 'status': 'error'}), 500

        # -------------------------
        # Enviar correo con adjunto
        # -------------------------
        # Remitente y destinatarios
        sender = current_app.config.get('MAIL_USERNAME')
        event_provider_email = sales[0].event_rel.provider.ProviderEmail

        admins = EventsUsers.query.filter(EventsUsers.role.in_(['admin'])).all()

        admins_emails = [admin.Email for admin in admins if admin.Email]

        recipients = [sender, event_provider_email]  # Enviar al admin

        recipients = list(set(recipients + admins_emails))  # Evitar duplicados

        attachment_filename = f"liquidation_{liquidation.LiquidationID}.pdf"

        if not sender:
            logging.error("No se configuró SENDER_EMAIL para enviar correos")
            # No consideramos esto crítico para la creación de la liquidación; devolvemos éxito pero advertencia
            return jsonify({
                "message": "liquidación creada con éxito, pero no se pudo enviar correo (SENDER no configurado)",
                "status": "ok",
                "s3_key": s3_key
            }), 200

        try:
            emailed = utils_backend.send_email_with_attachment(sender, recipients, pdf_bytes, attachment_filename)
            if not emailed:
                logging.error("Fallo al enviar correo de liquidación")
                # No revertimos DB; informamos al cliente
                return jsonify({
                    "message": "liquidación creada, pero fallo al enviar correo",
                    "status": "ok",
                    "s3_key": s3_key
                }), 200
        except Exception as e:
            logging.error(f"Error enviando correo de liquidación: {e}")
            return jsonify({
                "message": "liquidación creada, pero fallo al enviar correo",
                "status": "ok",
                "s3_key": s3_key
            }), 200


        db.session.commit()

        return jsonify({"message": "liquidación creada con éxito", "status": "ok"}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear evento: {e}")
        return jsonify({'message': 'Error al crear evento', 'status': 'error'}), 500
    finally:
        try:
            db.session.close()
        except Exception:
            pass

@backend.route('/view-liquidations', methods=['GET']) #ver paquetes o ventas en general
@roles_required(allowed_roles=["admin"])
def view_liquidations():
    try:
        event_str = request.args.get('id_event', '')

        if not event_str or not event_str.isdigit():
            return jsonify({'message': 'faltan parámetros o formato inválido', 'status': 'error'}), 400

        liquidations = Liquidations.query.options(
            # eager-load provider basic fields
            joinedload(Liquidations.provider).load_only(Providers.ProviderName, Providers.ProviderEmail),
            # eager-load sales and their tickets and seat->section to avoid N+1
            joinedload(Liquidations.sales)
                .load_only(Sales.sale_id, Sales.price, Sales.saleLink)
                .joinedload(Sales.tickets)
                    .load_only(Ticket.ticket_id, Ticket.price, Ticket.seat_id)
                    .joinedload(Ticket.seat)
                        .load_only(Seat.section_id, Seat.row, Seat.number)
                        .joinedload(Seat.section)
                            .load_only(Section.section_id, Section.name),
            # load only necessary liquidation fields (include Discount and AdditionalFees used later)
            load_only(Liquidations.LiquidationID, Liquidations.EventID, Liquidations.Amount, Liquidations.AmountBS, Liquidations.LiquidationDate, Liquidations.CreatedBy, Liquidations.Comments, Liquidations.Discount, Liquidations.AdditionalFees)
        ).filter(Liquidations.EventID == int(event_str)).all()

        liquidations_data = []

        if liquidations:

            event_info = {
                "event_id": liquidations[0].sales[0].event_rel.event_id,
                "provider_name": liquidations[0].sales[0].event_rel.provider.ProviderName,
                "event": liquidations[0].sales[0].event_rel.name,
                "event_date": liquidations[0].sales[0].event_rel.date_string,
                "event_hour": liquidations[0].sales[0].event_rel.hour_string,
                "event_place": liquidations[0].sales[0].event_rel.venue.name,
                "total_liquidated": round((liquidations[0].sales[0].event_rel.liquidado if liquidations[0].sales[0].event_rel.liquidado else 0)/100, 2),
                "total_sales": (liquidations[0].sales[0].event_rel.total_sales if liquidations[0].sales[0].event_rel.total_sales else 0),
                "gross_sales": round((liquidations[0].sales[0].event_rel.gross_sales if liquidations[0].sales[0].event_rel.gross_sales else 0)/100, 2),
                "total_fees": round((liquidations[0].sales[0].event_rel.total_fees if liquidations[0].sales[0].event_rel.total_fees else 0)/100, 2),
            }

            for liquidation in liquidations:

                liquidation_dict= {
                    'liquidation_id': liquidation.LiquidationID,
                    'event_id': liquidation.EventID,
                    'amount_usd': round(liquidation.Amount/100, 2),
                    'amount_bsd': round(liquidation.AmountBS/100, 2),
                    'liquidation_date': liquidation.LiquidationDate.isoformat() if liquidation.LiquidationDate else '',
                    'created_by': liquidation.CreatedBy,
                    'comments': liquidation.Comments,
                    'payment_method': liquidation.PaymentMethod,
                    'reference': liquidation.Reference
                }

                if liquidation.Discount:
                    discounts_list = []
                    discounts_items = liquidation.Discount.split('||')
                    for item in discounts_items:
                        try:
                            name, price = item.split(',', 1)
                            discounts_list.append({
                                'name': name,
                                'price': int(price)
                            })
                        except Exception:
                            continue
                    liquidation_dict['discounts'] = discounts_list

                if liquidation.AdditionalFees:
                    additional_fees_list = []
                    additional_fees_items = liquidation.AdditionalFees.split('||')
                    for item in additional_fees_items:
                        try:
                            name, price = item.split(',', 1)
                            additional_fees_list.append({
                                'name': name,
                                'price': int(price)
                            })
                        except Exception:
                            continue
                    liquidation_dict['additional_charges'] = additional_fees_list

                if liquidation.sales:
                    tickets = []
                    for sale in liquidation.sales:
                        if not sale.tickets:
                            continue
                        for ticket in sale.tickets:
                            tickets.append({
                                'ticket_id': ticket.ticket_id,
                                'sale_id': sale.sale_id,
                                'price': round(ticket.price/100, 2),
                                'section': ticket.seat.section.name if ticket.seat and ticket.seat.section else '',
                                'row': ticket.seat.row if ticket.seat else '',
                                'number': ticket.seat.number if ticket.seat else '',
                                'dateofPurchase': ticket.emission_date.isoformat() if ticket.emission_date else ''
                            })
                    liquidation_dict['tickets'] = tickets

                liquidations_data.append(liquidation_dict)
            liquidations_data.sort(key=lambda x: x['liquidation_date'], reverse=True)

            return jsonify({"liquidations": liquidations_data, "event": event_info ,"status": "ok"}), 200
            
        event_obj = Event.query.options(
            load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string, Event.venue_id, Event.liquidado, Event.total_sales, Event.gross_sales, Event.total_fees),
            joinedload(Event.provider).load_only(Providers.ProviderID, Providers.ProviderName),
            joinedload(Event.venue).load_only(Venue.venue_id, Venue.name)
        ).filter(Event.event_id == int(event_str)).one_or_none()

        if not event_obj:
            return jsonify({"message": "No se encontró el evento"}), 404
        
        event_info = {
            "event_id": event_obj.event_id,
            "provider_name": event_obj.provider.ProviderName if (event_obj.provider) else '',
            "event": event_obj.name,
            "event_date": event_obj.date_string,
            "event_hour": event_obj.hour_string,
            "event_place": event_obj.venue.name if event_obj.venue else '',
            "total_liquidated": round((event_obj.liquidado if event_obj.liquidado else 0)/100, 2),
            "total_sales": event_obj.total_sales,
            "gross_sales": round((event_obj.gross_sales if event_obj.gross_sales else 0)/100, 2),
            "total_fees": round((event_obj.total_fees if event_obj.total_fees else 0)/100, 2)
        }
        return jsonify({"event": event_info, "status": "ok"}), 200
    except Exception as e:
        logging.error(f"Error al procesar liquidación: {e}")
        return jsonify({'message': 'Error al procesar liquidaciones', 'status': 'error'}), 500
    finally:
        try:
            db.session.close()
        except Exception:
            pass

@backend.route('delete-liquidation', methods=['POST'])
@roles_required(allowed_roles=["admin"])
def delete_liquidation():
    try:
        data = request.get_json()
        liquidation_id = data.get('liquidationId', '')

        if not liquidation_id or not str(liquidation_id).isdigit():
            return jsonify({'message': 'Faltan parámetros o formato inválido', 'status': 'error'}), 400

        liquidation = Liquidations.query.filter(Liquidations.LiquidationID == int(liquidation_id)).one_or_none()

        if not liquidation:
            return jsonify({'message': 'No se encontró la liquidación', 'status': 'error'}), 404

        # Marcar las ventas asociadas como no liquidadas
        liquidated_amount_net = 0
        for sale in liquidation.sales: # recorrer las ventas asociadas a la liquidación
            sale.liquidado = False
            sale.liquidation_id = None
            liquidated_amount_net += sale.price # sumar el total de las ventas liquidadas

        liquidation.event.liquidado -= liquidated_amount_net if  liquidation.event.liquidado else liquidated_amount_net # Ajustar el total liquidado del evento

        db.session.delete(liquidation) # Eliminar la liquidación

        #ahora notificamos al proveedor por email y a los admins
        sender = current_app.config.get('MAIL_USERNAME')
        provider_email = liquidation.provider.ProviderEmail if liquidation.provider else None   
        admins = EventsUsers.query.filter(EventsUsers.role.in_(['admin'])).all()

        admins_emails = [admin.Email for admin in admins if admin.Email]

        recipients = [sender, provider_email]  # Enviar al admin
        recipients = list(set(recipients + admins_emails))  # Evitar duplicados

        if sender and provider_email:
            try:
                subject = f"Notificación de eliminación de liquidación #{liquidation.LiquidationID}"
                body_text = f"""
Estimado proveedor,

Le informamos que la liquidación con ID #{liquidation.LiquidationID} correspondiente al evento ID #{liquidation.EventID} ha sido eliminada del sistema por un administrador.

Si tiene alguna pregunta o necesita más información, no dude en contactarnos.

Atentamente,
Equipo de Fiesta Ticket
                """
                try:
                    msg = Message(subject, sender=sender, recipients=recipients)
                    msg.body = body_text

                    mail.send(msg)
                except Exception as e:
                    return jsonify({'message': 'Error enviando notificación por correo', 'status': 'error'}), 500
                
            except Exception as e:
                return jsonify({'message': 'Error enviando notificación por correo', 'status': 'error'}), 500

        db.session.commit()

        return jsonify({'message': 'Liquidación eliminada con éxito', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al eliminar liquidación: {e}")
        return jsonify({'message': 'Error al eliminar liquidación', 'status': 'error'}), 500
    finally:
        try:
            db.session.close()
        except Exception:
            pass

    
@backend.route('/load-available-tickets', methods=['GET'])
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_available_tickets():
    try:
        event_name = request.args.get('event', '')
        venue = request.args.get('venue', '')
        date_and_time = request.args.get('date', '')
        date, time = ('', '')
        tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
        tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')
        payment_method = request.args.get('payment_method', '')

        if not all([event_name, venue, date_and_time, payment_method, tickera_id, tickera_api_key]):
            return jsonify({"message": "Faltan parámetros"}), 400
        
        if ' - ' in date_and_time:
            date, time = date_and_time.split(' - ', 1)

        if not event_name or not venue or not date or not time:
            return jsonify({"message": "Faltan parámetros"}), 400

        # ✅ Cargar el evento con una sola query
        event = (
            Event.query.options(load_only(
                Event.event_id,
                Event.name,
                Event.financiamientos,
                Event.Type,
            ))
            .filter(
                and_(
                    Event.name == event_name,
                    Event.venue_id == venue,
                    Event.date_string == date,
                    Event.hour_string == time,
                )
            )
            .one_or_none()
        )

        if not event:
            return jsonify({"message": "No se encontró el evento"}), 404
        
        if event.active != True:
            return jsonify({"message": "El evento no está activo"}), 400
        
        #obtenemos las características adicionales del evento
        additional_features_list = []
        if event.additional_features:
            for feature in event.additional_features:

                if feature.Active != True:
                    continue
                accepted_payments = feature.accepted_payment_methods.split(',') if feature.accepted_payment_methods else ['all']
                if accepted_payments != ['all'] and payment_method.lower() not in [method.strip().lower() for method in accepted_payments]:
                    continue
                additional_features_list.append({
                    "FeatureID": feature.FeatureID,
                    "FeatureName": feature.FeatureName,
                    "FeatureDescription": feature.FeatureDescription,   
                    "FeaturePrice": feature.FeaturePrice,
                    "FeatureCategory": feature.FeatureCategory,                      
                })

        
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

            now = datetime.now(timezone.utc)  # Siempre en UTC

            tickets = response.json().get("tickets", [])
        else: #si no viene de la api
            tickets_local = (
                Ticket.query.options(
                    joinedload(Ticket.seat).load_only(Seat.section_id, Seat.row, Seat.number),
                    joinedload(Ticket.seat).joinedload(Seat.section).load_only(Section.name, Section.accepted_payment_methods),
                    load_only(Ticket.ticket_id, Ticket.status, Ticket.price, Ticket.expires_at)
                )
                .filter(Ticket.event_id == event.event_id)
                .all()
            )

            # Convertir a lista de diccionarios para un procesamiento uniforme
            tickets = [
                {
                    "ticket_id": t.ticket_id,
                    "status": t.status,
                    "price": t.price,
                    "number": t.seat.number,
                    "section": t.seat.section.name.replace('20_', ' ') if t.seat and t.seat.section else '',
                    "row": t.seat.row if t.seat else '',
                    "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                    "allowed_payment_methods": t.seat.section.accepted_payment_methods if t.seat and t.seat.section else 'all',  # agregar el método de pago solicitado
                }
                for t in tickets_local
            ]

            now = datetime.now(timezone.utc)  # Siempre en UTC


        now_ts = calendar.timegm(now.utctimetuple())
        # ✅ Procesar los tickets agrupados por sección y fila
        sections_dict = {}

        for t in tickets:
            if t["status"] in ["disponible", "en carrito"]:

                if t.get("allowed_payment_methods") and t["allowed_payment_methods"] != "all":
                    allowed_methods = [method.strip().lower() for method in t["allowed_payment_methods"].split(",")]
                    if payment_method.lower() not in allowed_methods:
                        continue

                # Comparación segura
                if t["status"] == "en carrito":
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

                    if expires_raw is None or expires_ts > now_ts:
                        continue

                number = t["number"]
                section = t["section"]
                row = t["row"]

                if section not in sections_dict:
                    sections_dict[section] = {"section": section, "rows": {}}
                if row not in sections_dict[section]["rows"]:
                    sections_dict[section]["rows"][row] = []

                sections_dict[section]["rows"][row].append({
                    "ticket_id": t["ticket_id"],
                    "price": t["price"],
                    "status": t["status"],
                    "number": number
                })

        # ✅ Convertir a lista
        tickets_list = [
            {
                "section": section,
                "rows": [
                    {"row": row, "seats": seats}
                    for row, seats in section_data["rows"].items()
                ],
            }
            for section, section_data in sections_dict.items()
        ]

        return jsonify({
            "tickets": tickets_list,
            "fee": event.Fee,
            "event_id": event.event_id,
            "BsDExchangeRate": BsDexchangeRate,
            "additionalFeatures": additional_features_list,
            "status": "ok"
        }), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al cargar boletos disponibles: {e}", exc_info=True)
        return jsonify({'message': 'Error interno', 'status': 'error'}), 500

@backend.route('/load-boleteria', methods=['GET']) #ruta para ver los boletos que se han vendido
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_boleteria():
    try:
        now = datetime.now(timezone.utc)  # Siempre en UTC
        event_id = request.args.get('query', '')
        if not event_id.isdigit():
            return jsonify({"message": "ID de evento inválido"}), 400

        event = Event.query.filter_by(event_id=int(event_id)).one_or_none()
        if not event:
            return jsonify({"message": "No se encontró el evento"}), 404

        tickets_list = []
        tickets_stats = {}

        tickets = (
            Ticket.query.options(
                joinedload(Ticket.customer),
                joinedload(Ticket.seat).joinedload(Seat.section),
                joinedload(Ticket.event),
                load_only(
                    Ticket.ticket_id, Ticket.status, Ticket.price, Ticket.discount, Ticket.fee,
                    Ticket.saleLocator, Ticket.saleLink, Ticket.QRlink, Ticket.blockedBy,
                    Ticket.seat_id, Ticket.event_id, Ticket.customer_id
                )
            )
            .filter(
                Ticket.event_id == event.event_id,
                or_
                (Ticket.status == 'pagado',
                Ticket.status == 'reservado',
                Ticket.blockedBy != None)
            )
            .all()
        )

        # Contar tickets por estado en una sola consulta
        tickets_counts = dict(
            db.session.query(
                Ticket.status, func.count(Ticket.ticket_id)
            )
            .filter(Ticket.event_id == event.event_id)
            .group_by(Ticket.status)
            .all()
        )

        tickets_stats = {
            "available_tickets": tickets_counts.get("disponible", 0),
            "blocked_tickets": tickets_counts.get("bloqueado", 0),
            "reserved_tickets": sum(
                tickets_counts.get(s, 0) for s in ["reservado", "pagado por verificar", "por cuotas", "pendiente pago"]
            ),
            "paid_tickets": tickets_counts.get("pagado", 0),
            "encarrito_tickets": tickets_counts.get("en carrito", 0),
        }

        
        #validamos los tickets que estan expirados, si estan en carrito y ya pasaron su tiempo, los contamos como disponibles
        expired_en_carrito_count = 0
        for status, count in tickets_counts.items():
            if status == 'en carrito':
                for t in tickets:
                    if t.status == 'en carrito':
                        if t.expires_at and t.expires_at.tzinfo is None:
                            expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
                        else:
                            expires_at_aware = t.expires_at # Ya tiene info de zona horaria
                        if not expires_at_aware or expires_at_aware <= now:
                            expired_en_carrito_count += 1

        tickets_stats["available_tickets"] += expired_en_carrito_count
        tickets_stats["encarrito_tickets"] -= expired_en_carrito_count

        SVGmap = event.SVGmap if event.SVGmap else ""

        for t in tickets:

            if t.status == 'en carrito':
                if t.expires_at and t.expires_at.tzinfo is None:
                    expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
                else:
                    expires_at_aware = t.expires_at # Ya tiene info de zona horaria
                if not expires_at_aware or expires_at_aware <= now:
                    # Si el ticket está "en carrito" pero ha expirado, lo marcamos como disponible
                    continue  # No lo incluimos en la lista de tickets disponibles
            

            tickets_list.append({
                "sale_id": t.ticket_id,
                "fullname": f"{t.customer.FirstName} {t.customer.LastName}" if t.customer else "",
                "status": t.status,
                "price": round((t.price - t.discount) / 100, 2) if t.price else 0,
                "saleLocator": t.saleLocator,
                "saleLink": t.saleLink,
                "QRlink": t.QRlink,
                "email": t.customer.Email if t.customer else "",
                "section": t.seat.section.name if t.seat else "",
                "row": t.seat.row if t.seat else "",
                "number": t.seat.number if t.seat else "",
                "event": t.event.name,
                "date": t.event.date_string,
                "hour": t.event.hour_string,
                "place": t.event.venue.name,
                "blockedBy": t.blockedBy,
            })

        return jsonify({
            "status": "ok",
            "type": event.Type,
            "event": event.name,
            "date": event.date_string,
            "hour": event.hour_string,
            "place": event.venue.name,
            "stats": tickets_stats,
            "tickets": tickets_list,
            "venue_map": SVGmap
        }), 200

    except ValueError:
        return jsonify({"message": "ID de evento inválido"}), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al cargar boleteria: {e}", exc_info=True)
        return jsonify({"message": "Error interno al cargar boleteria", "status": "error"}), 500

@backend.route('/load-map', methods=['GET'])
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_map():
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
            tickets_list = []
            tickets = response.json().get("tickets", [])

            now = datetime.now(timezone.utc)  # Siempre en UTC

            for t in tickets:
                status = t.get("status", "desconocido")
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
                
                if status not in ["disponible", "en carrito"]:
                    status = "bloqueado"
                    
                tickets_list.append({
                    "ticket_id": t["ticket_id"],
                    "status": status,
                    "row": t["row"],
                    "number": t["number"],
                    "section": t["section"],
                    "price": t["price"],
                    "svg_id": t["svg_id"],
                    "expires_at": t["expires_at"],
                    "sale_id": None
                })
            process_end = time.perf_counter()
            
            total_end = time.perf_counter()
            print(f"⏱ Tiempos (segundos):")
            print(f"  - DB lookup: {db_end - db_start:.4f}")
            print(f"  - Request externo: {req_end - req_start:.4f}")
            print(f"  - Procesamiento respuesta: {process_end - process_start:.4f}")
            print(f"  - Total: {total_end - start_time:.4f}")

            # ---------------------------------------------------------------
            # 3️⃣ Hacer query a base de datos local
            # ---------------------------------------------------------------

            tickets_local = Ticket.query.filter(
                Ticket.event_id == event.event_id,
                or_(
                    Ticket.status == 'pagado',
                    Ticket.status == 'pagado por verificar',
                    Ticket.status == 'en carrito',
                    Ticket.status == 'pendiente pago',
                )
            ).all()

            #actualizamos los estados de los tickets segun la base de datos local
            local_status_dict = {t.ticket_id_provider: t.status for t in tickets_local}
            local_saleID_dict = {t.ticket_id_provider: t.sale_id for t in tickets_local}
            for t in tickets_list:
                local_status = local_status_dict.get(t["ticket_id"])
                if local_status:
                    if local_status == "en carrito":
                        # Verificar expiración
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

                        if expires_raw is None or expires_ts <= now_ts:
                            local_status = "disponible"
                    t["status"] = local_status

            for t in tickets_list:
                t["sale_id"] = local_saleID_dict.get(t["ticket_id"])

            event_details  = {  
                "name": event.name,
                "date": event.date_string,
                "hour": event.hour_string,
                "place": event.venue.name if event.venue else None
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
            print(f"⏱ Request externo fallido en {req_end - req_start:.4f} segundos")

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

@backend.route('/new-massive-block-of-tickets', methods=['PUT']) #permite subir un csv o excel con los boletos que han sido bloqueados para tickeras o ventas de terceros
@roles_required(allowed_roles=["admin", "tiquetero"])
def new_massive_block_of_tickets():
    try:
        user_id = get_jwt().get("id")

        # 1. Extraer datos del formulario
        event_id = request.args.get('query', '')
        seat_file = request.files.get('seatFile')

        now = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)  # Siempre en UTC

        if not all([event_id, seat_file]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

        if not allowed_file(seat_file.filename):
            return jsonify({'message': 'Formato de archivo no permitido', 'status': 'error'}), 400
        
        event = Event.query.filter_by(event_id=event_id).first()

        venue_id = event.venue_id

        # 2. Leer el archivo con pandas (soporta csv y excel)
        if seat_file.filename.endswith('.csv'):
            df = pd.read_csv(seat_file)
        else:
            df = pd.read_excel(seat_file)

        # Normalizamos nombres de columnas
        df.columns = df.columns.str.strip().str.lower()

        # Validar que tenga las columnas correctas
        required_cols = {'asiento', 'seccion', 'by', 'fee', 'discount'}
        if not required_cols.issubset(df.columns):
            return jsonify({'message': 'El archivo no tiene las columnas requeridas', 'status': 'error'}), 400

        # 5. Procesar cada fila del archivo
        for _, row in df.iterrows():
            asiento = str(row['asiento']).strip()
            seccion = str(row['seccion']).strip()
            discount = str(row['discount']).strip()
            fee = str(row['fee']).strip()
            by = str(row['by']).strip()

            # Dividir el asiento en fila y número
            row_label = ''.join([ch for ch in asiento if ch.isalpha()])
            number = ''.join([ch for ch in asiento if ch.isdigit()])

            section = Section.query.filter(
                and_(Section.name == seccion, Section.venue_id == venue_id)
            ).first()

            if not section:
                return jsonify({'message': f'No se encontró la sección {seccion} en el venue', 'status': 'error'}), 400

            seat = Seat.query.filter_by(section_id=section.section_id, row=row_label, number=number).first()

            if not seat:
                return jsonify({'message': f"No se encontró el asiento {asiento} de la fila {row_label} de la seccion {seccion}", 'status': 'error'}), 400

            # Modificar Ticket
            ticket = Ticket.query.filter(
                and_(Ticket.seat_id == seat.seat_id, Ticket.event_id == event_id)
            ).first()

            if not ticket:
                return jsonify({'message': f'No se encontró el ticket para el asiento {asiento} de la fila {row_label} de la seccion {seccion}', 'status': 'error'}), 400

            if ticket.status not in ['disponible', 'en carrito']:
                return jsonify({'message': f"El asiento {asiento} de la fila {row_label} de la seccion {seccion} no esta disponible, modifique su status antes de bloquearlo", 'status': 'error'}), 400
            
            if ticket.status == 'en carrito':
                if ticket.expires_at and ticket.expires_at.tzinfo is None:
                    expires_at_aware = ticket.expires_at.replace(tzinfo=timezone.utc)
                else:
                    expires_at_aware = ticket.expires_at # Ya tiene info de zona horaria
                if expires_at_aware > now:
                    return jsonify({'message': f"El asiento {asiento} de la fila {row_label} de la seccion {seccion} está en carrito por otro usuario, no se puede bloquear", 'status': 'error'}), 400

            ticket.status = 'bloqueado'
            ticket.blockedBy = by
            ticket.fee = int(fee*100)
            ticket.discount = int(discount*100)

        log_for_massive_block = Logs(
            UserID=user_id,
            Type='bloqueo masivo de boletos',
            Timestamp=datetime.now(),
            Details=f"Se han bloqueado tickets de forma masiva para el evento{event.name}",
        ) 
        db.session.add(log_for_massive_block)

        db.session.commit()

        return jsonify({'message': 'bloqueo masivo exitoso', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al bloquear boletos: {e}")
        return jsonify({'message': 'Error al bloquear boletos', 'status': 'error'}), 500
    
@backend.route('/unblock-ticket', methods=['GET']) #para desbloquear un boleto vendido por un tercero
@roles_required(allowed_roles=["admin", "tiquetero"])
def unblock_ticket():
    try:
        user_id = get_jwt().get("id")

        # 1. Extraer datos del formulario
        ticket_id = request.args.get('query', '')

        if not all([ticket_id]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

        # Modificar Ticket
        ticket = Ticket.query.filter(
            and_(Ticket.ticket_id == int(ticket_id))
        ).one_or_none()

        if not ticket:
            return jsonify({'message': f'No se encontró el ticket', 'status': 'error'}), 400

        if ticket.status != 'bloqueado' or not ticket.blockedBy:
            return jsonify({'message': f"El asiento no se encuentra bloqueado actualmente", 'status': 'error'}), 400

        ticket.status = 'disponible'
        ticket.blockedBy = None
        ticket.discount = 0
        ticket.fee = 0

        log_for_block = Logs(
            UserID=user_id,
            Type='boleto desbloqueado',
            Timestamp=datetime.now(),
            Details=f"Se ha desbloqueado el ticket de ID {ticket_id} (Asiento {ticket.seat.row}{ticket.seat.number}) del evento {ticket.event.name}",
        ) 
        db.session.add(log_for_block)

        db.session.commit()

        return jsonify({'message': 'ticket desbloqueado exitosamente', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al desbloquear ticket: {e}")
        return jsonify({'message': 'Error al desbloquear ticket', 'status': 'error'}), 500
    
@backend.route('/block-tickets', methods=['POST'])
@roles_required(allowed_roles=["admin", "tiquetero"])
def block_tickets():
    user_id = get_jwt().get("id")
    data = request.get_json()

    payment_method = data.get("PaymentMethod")
    payment_reference = data.get("PaymentReference")
    contact_phone = data.get("phone")
    contact_phone_prefix = data.get("countryCode")
    selectedSeats = data.get('selectedSeats')
    email = request.json.get('email')
    firstname = bleach.clean(request.json.get('firstname', ''), strip=True)
    lastname = bleach.clean(request.json.get('lastname', ''), strip=True)
    date = request.json.get('PaymentDate')
    cedula = request.json.get('cedula', '').strip()
    address = bleach.clean(request.json.get('shortAddress', ''), strip=True)
    discount_code = bleach.clean(request.json.get('discount_code', ''), strip=True)
    
    # Add support for addons (modernization)
    addons = request.json.get('addons', [])

    tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
    tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

    # ----------------------------------------------------------------
    # 1️⃣ Validaciones iniciales
    # ----------------------------------------------------------------
    if not all([user_id, payment_method, selectedSeats, payment_reference, email, firstname, lastname, date, contact_phone, contact_phone_prefix, cedula, address]):
        return jsonify({"message": "Faltan parámetros obligatorios"}), 400

    if payment_method not in ["pagomovil", "efectivo", "zelle", "binance", "square", "tarjeta de credito", "paypal", "stripe", "pos", "cashea"]:
        return jsonify({"message": "Método de pago no válido"}), 400
    
    if len(selectedSeats) == 0:
        return jsonify({"message": "No se seleccionaron asientos"}), 400
    
    email = email.strip().lower()
    if not utils.email_pattern.match(email):
        return jsonify({"message": "Correo electrónico no válido"}), 400
    
    if not utils.cedula_pattern.match(cedula):
        return jsonify({"message": "Cédula no válida"}), 400
    
    cedula =cedula.upper()

    # ----------------------------------------------------------------
    # 2️⃣ Validar información del pago
    # ----------------------------------------------------------------

    if not all([contact_phone, contact_phone_prefix]):
        return jsonify({"message": "Complete todos los campos requeridos"}), 400

    if not utils.phone_pattern.match(contact_phone):
        return jsonify({"message": "Número de teléfono no válido"}), 400

    if not utils.country_code_pattern.match(contact_phone_prefix):
        return jsonify({"message": "Código de país no válido"}), 400

    payment_status = "pagado por verificar"

    # ----------------------------------------------------------------
    # 3️⃣ Validar cliente
    # ----------------------------------------------------------------
    customer = EventsUsers.query.filter_by(Email=email).one_or_none()
    if customer:
        if customer.status.lower() == "suspended":
            return jsonify({"message": "Su cuenta está suspendida."}), 403
    else:
        customer = EventsUsers(
            FirstName=firstname.strip(),
            LastName=lastname.strip(),
            Email=email,
            role='passive_customer',
            status='unverified',
            CreatedBy=user_id,
            Identification=cedula,
            PhoneNumber=contact_phone,
            CountryCode=contact_phone_prefix,
            Address=address
        )
        db.session.add(customer)
        db.session.flush()  # para obtener customer_id

    # ----------------------------------------------------------------
    # 4️⃣ Obtener tickets seleccionados
    # ----------------------------------------------------------------
    ticket_ids = [int(s['ticket_id']) for s in selectedSeats if 'ticket_id' in s]

    tickets_en_carrito = Ticket.query.options(
        joinedload(Ticket.seat).joinedload(Seat.section),
        joinedload(Ticket.event)
    ).filter(
        Ticket.ticket_id.in_(ticket_ids)
    ).all()

    if not tickets_en_carrito or len(tickets_en_carrito) != len(ticket_ids):
        return jsonify({"message": "Algunos tickets no están disponibles"}), 400

    event = tickets_en_carrito[0].event

    if not event or not event.active:
        return jsonify({"message": "Evento no encontrado o inactivo"}), 404

    # ----------------------------------------------------------------
    # 5️⃣ Validar y preparar descuentos
    # ----------------------------------------------------------------
    total_discount = 0
    discount_id = None

    # Sanitizar tickets_en_carrito
    def clean_tickets(list_in):
        out = []
        if not list_in:
            return out
        for i, t in enumerate(list_in):
            tid = t.ticket_id_provider if event.from_api else t.ticket_id
            price = t.price
            try:
                tid_i = int(tid)
            except Exception:
                continue
            out.append({"ticket_id_provider": tid_i, "price": str(price), "discount": str(0)})
            if len(out) >= 200:
                break
        return out

    if discount_code:
        discount_code = bleach.clean(discount_code.upper(), strip=True)
        validated_discount = utils.validate_discount_code(discount_code, customer, event, tickets_en_carrito, 'block')
        if not validated_discount["status"]:
            return jsonify({"message": "Código de descuento inválido"}), 400
        total_discount = validated_discount['total_discount']
        tickets_payload = validated_discount['tickets']
        discount_id = validated_discount['discount_id']
    else:
        tickets_payload = clean_tickets(tickets_en_carrito)

    # ----------------------------------------------------------------
    # 6️⃣ Bloquear en Tickera (solo si event.from_api == True)
    # ----------------------------------------------------------------
    if event.from_api:
        if not all([tickera_id, tickera_api_key]):
            return jsonify({"message": "Configuración de API externa incompleta"}), 500
            
        url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/block-tickets"

        # Normalizar event id
        event_id = str(event.event_id_provider).strip()
        if not event_id or not event_id.isdigit() or len(event_id) > 64:
            raise ValueError("event_id inválido")

        if not tickets_payload:
            raise ValueError("No hay tickets válidos para bloquear")

        payload = {
            "event": event_id,
            "tickets": tickets_payload,
            "type_of_sale": "admin_sale"
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

            response.raise_for_status()

            try:
                data = response.json()
            except ValueError:
                logging.error("JSON inválido en respuesta de block-tickets")
                raise

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
    # 7️⃣ Aplicar cambios locales (una sola transacción)
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
            user_id=customer.CustomerID,
            status=payment_status,
            created_by=user_id,
            StatusFinanciamiento='decontado',
            event=event.event_id,
            fee=total_fee,
            ContactPhoneNumber=contact_phone,
            creation_date=date,
            discount=total_discount,
            discount_ref=discount_id
        )
        db.session.add(sale)
        db.session.flush()

        # ----------------------------------------------------------------
        # 8️⃣ Validar y registrar addons (modernización)
        # ----------------------------------------------------------------
        validated_addons = []
        
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
                total_price += int(addon["Quantity"]) * int(addon["FeaturePrice"])
            sale.price = total_price
            db.session.flush()

        # Actualizar tickets
        for t in tickets_en_carrito:
            t.status = payment_status
            t.sale_id = sale.sale_id
            t.fee = round((event.Fee or 0) * t.price / 100, 2)
            t.expires_at = None
            t.customer_id = customer.CustomerID
            t.blockedBy = None

        today = datetime.utcnow().date()

        payment = Payments(
            SaleID=sale.sale_id,
            Amount=total_price + total_fee - total_discount,
            PaymentDate=today,
            PaymentMethod=payment_method,
            Reference=payment_reference,
            Status='pendiente',
            CreatedBy=user_id,
        )
        db.session.add(payment)

        # ----------------------------------------------------------------
        # 9️⃣ Enviar notificación según método de pago
        # ----------------------------------------------------------------
        serializer = current_app.config['serializer']
        token = serializer.dumps({'user_id': user_id, 'sale_id': sale.sale_id})
        qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={token}'
        localizador = os.urandom(3).hex().upper()

        sale.saleLink = token
        sale.saleLocator = localizador

        sale_data = {
            'sale_id': sale.sale_id,
            'event': sale.event_rel.name,
            'venue': sale.event_rel.venue.name,
            'date': sale.event_rel.date_string,
            'hour': sale.event_rel.hour_string,
            'price': round(sale.price / 100, 2),
            'discount': round(sale.discount / 100, 2),
            'fee': round(sale.fee / 100, 2),
            'total_abono': round((total_price + sale.fee - sale.discount) / 100, 2),
            'due': round(0, 2),
            'payment_method': payment_method.capitalize(),
            'payment_date': today.strftime('%d-%m-%Y'),
            'reference': payment_reference or 'N/A',
            'link_reserva': qr_link,
            'localizador': localizador,
            'status': 'pagado',
            'title': 'Estamos procesando tu abono',
            'subtitle': 'Te notificaremos una vez que haya sido aprobado',
            'add_ons': validated_addons if validated_addons else None,
            'is_package_tour': event.type_of_event == 'paquete_turistico',
            'currency': 'usd'
        } 
        
        if total_discount > 0:
            if discount_code:
                discount = Discounts.query.filter(Discounts.Code == discount_code).first()
                if discount:
                    discount.UsedCount = (discount.UsedCount or 0) + 1

        # Confirmar todo
        db.session.commit()

        # ---------------------------------------------------------------
        # Enviar notificación por email al cliente
        # ---------------------------------------------------------------

        #utils.sendnotification_for_PaymentStatus(current_app.config, db, mail, customer, selectedSeats, sale_data)

        # ---------------------------------------------------------------
        # Notificar a administración sobre nueva venta/pago por whatsapp
        # ---------------------------------------------------------------
        WA_utils.send_new_sale_notification(current_app.config, customer, selectedSeats, sale_data, contact_phone)
        # ---------------------------------------------------------------

        return jsonify({"message": "Tickets bloqueados y venta registrada exitosamente", "status": "ok"}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error registrando venta o pago: {str(e)}")
        return jsonify({"message": "Error al registrar la venta o pago", "status": "error"}), 500
    finally:
        db.session.close()

@backend.route('/customize-reservation', methods=['GET']) #endpoint para recopilar informacion de la reserva (admin)
@roles_required(allowed_roles=["admin", "tiquetero"])
def customize_reservation():
    sale_id = request.args.get('query', '')

    def format_amount(cents):
        try:
            return round(int(cents) / 100, 2)
        except Exception:
            return 0.0

    def build_payments_list(payments_query):
        out = []
        for entry in payments_query:
            out.append({
                'amount': format_amount(entry.Amount),
                'date': entry.PaymentDate,
                'paymentMethod': entry.PaymentMethod,
                'paymentReference': entry.Reference,
                'paymentVerified': entry.Status
            })
        return out

    def build_tickets_from_sale(sale):
        raw_ids = sale.ticket_ids or ''
        ticket_ids = [int(t) for t in raw_ids.split('|') if t.isdigit()]
        tickets = []

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
                    'number': seat.number if seat else None,
                    'QRlink': (f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/tickets?query={t.saleLink}') if sale.StatusFinanciamiento == 'pagado' else None
                })

        return tickets

    def parse_due_dates_field(due_dates_field):
        out = []
        if not due_dates_field:
            return out
        entries = due_dates_field.split('||') if '||' in due_dates_field else [due_dates_field]
        for entry in entries:
            try:
                due_date, amount, paid = entry.split('|', 2)
            except Exception:
                continue
            out.append({
                'due_date': due_date,
                'amount': format_amount(amount),
                'paid': paid == 'True'
            })
        return out

    try:
        if not sale_id:
            return jsonify({'message': 'Reserva no encontrada', 'status': 'error'}), 400

        sale = Sales.query.filter(Sales.sale_id == int(sale_id)).one_or_none()
        if not sale:
            return jsonify({'message': 'Reserva no encontrada', 'status': 'ok', 'reservation_status': 'missing'}), 400

        if sale.status == 'cancelado':
            return jsonify({'message': 'Reserva cancelada, por favor contacta a un administrador', 'status': 'ok', 'reservation_status': 'broken'}), 400

        payments = Payments.query.filter(Payments.SaleID == sale.sale_id).all()
        payments_list = build_payments_list(payments)

        event_name = sale.event_rel.name if sale.event_rel else ''
        venue_name = sale.event_rel.venue.name if sale.event_rel and sale.event_rel.venue else ''
        event_date = sale.event_rel.date_string if sale.event_rel else ''
        event_hour = sale.event_rel.hour_string if sale.event_rel else ''

        tickets = build_tickets_from_sale(sale)

        fee = sale.fee if sale.fee else 0
        discount = sale.discount if sale.discount else 0

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
                
        common_info = {
            'payments': payments_list,
            'items': tickets,
            'subtotal': format_amount(sale.price),
            'total_price': format_amount((sale.price or 0) + fee - discount),
            'paid': format_amount(sale.paid),
            'due': format_amount((sale.price or 0) + fee - discount - (sale.paid or 0)),
            'fee': round(fee / 100, 2),
            'discount': round(discount / 100, 2),
            'status': sale.status,
            'event': event_name,
            'venue': venue_name,
            'date': event_date,
            'hour': event_hour,
            'locator': sale.saleLocator,
            'StatusFinanciamiento': sale.StatusFinanciamiento,
            'Fullname': [(sale.customer.FirstName + ' ' + sale.customer.LastName) if sale.customer else ''],
            'Email': [sale.customer.Email if sale.customer else ''],
            'sale_id': sale.sale_id,
            'features': features
        }

        information = {}

        financiamiento = getattr(sale, 'financiamiento_rel', None)
        financiamiento_type = financiamiento.Type if financiamiento and hasattr(financiamiento, 'Type') else None

        if financiamiento and financiamiento_type == 'reserva':
            # reserva: fecha limite simple, payments list, etc.
            information.update(common_info)
            information['due_date'] = [financiamiento.Deadline] if hasattr(financiamiento, 'Deadline') else []
            information['payments'] = payments_list
            information['type'] = financiamiento_type
            information['items'] = tickets
            # keep compatibility with prior code that used 'saleId' once (normalize to sale_id)
            # previously returned 'saleId' in first branch — now standardized
        elif financiamiento and financiamiento_type == 'por cuotas':
            due_dates = parse_due_dates_field(sale.due_dates)
            information.update(common_info)
            information['due_dates'] = [due_dates]
            information['payments'] = payments_list
            information['type'] = financiamiento_type
            information['items'] = tickets
        else:
            # decontado / default
            due_dates = parse_due_dates_field(sale.due_dates)
            information.update(common_info)
            information['due_dates'] = [due_dates]
            information['payments'] = payments_list
            information['type'] = "decontado"
            information['items'] = tickets

        return jsonify({'message': 'Reserva existente', 'status': 'ok', 'information': information}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar reserva: {e}", exc_info=True)
        return jsonify({'message': 'Error al buscar reserva', 'status': 'error'}), 500
    
@backend.route('/new-abono', methods=['POST']) #pagos realizados por el cliente
@roles_required(allowed_roles=["admin", "tiquetero"])
def new_abono():
    try:
        user_id = get_jwt().get("id")

        # 1. Extraer datos del formulario
        sale_id = request.json.get('sale_id')
        received = request.json.get('received')
        PaymentMethod = request.json.get('PaymentMethod')
        PaymentDate = request.json.get('PaymentDate')
        PaymentReference = request.json.get('PaymentReference')

        if not all([sale_id, received, PaymentMethod, PaymentDate, PaymentReference]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400
        
        sale = Sales.query.filter(
            and_(
                Sales.sale_id == int(sale_id),
            )
        ).one_or_none()

        if not sale:
            return jsonify({'message': 'No se encontró la venta asociada', 'status': 'error'}), 400

        if sale.status == 'cancelado':
            return jsonify({'message': 'La venta está cancelada, no se pueden agregar abonos', 'status': 'error'}), 400
        
        fee = sale.fee if sale.fee else 0
        discount = sale.discount if sale.discount else 0

        # BUG FIX: Verificar que el total pagado no exceda el total a pagar
        # Total a pagar = (precio base + fee - descuento)
        total_due = sale.price + fee - discount
        total_after_payment = sale.paid + received
        if total_after_payment > total_due:
            return jsonify({'message': 'El monto abonado excede el total de la venta. El abono no puede ser procesado.', 'status': 'error'}), 400

        log_for_abono = Logs(
            UserID=user_id,
            Type='abono',
            Timestamp=datetime.now(),
            Details=f"Abono de {received} para la venta {sale_id}",
            SaleID=sale_id
        ) 
        db.session.add(log_for_abono)
        
        # Actualizar el campo payments
        new_payment_entry = Payments(
            SaleID=sale.sale_id,
            Amount=received,
            PaymentDate=PaymentDate,
            PaymentMethod=PaymentMethod,
            Reference=PaymentReference,
            Status='pendiente',
            CreatedBy=user_id
        )
        db.session.add(new_payment_entry)
        db.session.flush()

        # Actualizar el campo paid en la tabla Sales

        #customer
        customer = new_payment_entry.sale.customer
        #verificamos que tipo de evento es  

        Tickets = []
        
        ticket_ids = new_payment_entry.sale.ticket_ids.split('|') if '|' in new_payment_entry.sale.ticket_ids else [new_payment_entry.sale.ticket_ids]
        for ticket_id in ticket_ids:
            if ticket_id:
                ticket = Ticket.query.get(int(ticket_id))
                if ticket:
                    fee = ticket.fee if ticket.fee else 0
                    discount = ticket.discount if ticket.discount else 0

                    t = {
                        'ticket_id': ticket.ticket_id,  
                        'row': ticket.seat.row,
                        'number': ticket.seat.number,
                        'section': ticket.seat.section.name,
                        'event': ticket.price,
                        'price': round(ticket.price/100, 2),
                        'fee': round(fee/100, 2),
                        'discount': round(discount/100, 2)
                    }
                    Tickets.append(t)

        qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={new_payment_entry.sale.saleLink}'
    
        sale_data = {
            'sale_id': new_payment_entry.sale.sale_id,
            'event': new_payment_entry.sale.event_rel.name,
            'venue': new_payment_entry.sale.event_rel.venue.name,
            'date': new_payment_entry.sale.event_rel.date_string,
            'hour': new_payment_entry.sale.event_rel.hour_string,
            'price': round(new_payment_entry.sale.price/100, 2),
            'fee': round(new_payment_entry.sale.fee/100, 2),
            'discount': round(new_payment_entry.sale.discount/100, 2),
            'total_abono': round(received/100, 2),
            'due': round((new_payment_entry.sale.price + new_payment_entry.sale.fee - new_payment_entry.sale.discount)/100, 2),
            'payment_method': PaymentMethod,
            'payment_date': PaymentDate,
            'reference': PaymentReference,
            'link_reserva': qr_link,
            'deadline_reserva': new_payment_entry.sale.financiamiento_rel.Deadline,
            'localizador': new_payment_entry.sale.saleLocator,
            'status': 'pendiente',
            'title': 'Estamos procesando tu abono',
            'subtitle': 'Te notificaremos una vez que haya sido aprobado',
        }

        utils.sendnotification_for_PaymentStatus(current_app.config, db, mail, customer, Tickets, sale_data)

        db.session.commit()

        return jsonify({'message': 'Abono registrado exitosamente', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar reserva: {e}")
        return jsonify({'message': 'Error al buscar reserva', 'status': 'error'}), 500
    
@backend.route('/pending-payments', methods=['GET']) #para ver los pagos que quedan por ser confirmados
@roles_required(allowed_roles=["admin"])
def pending_payments():
    try:
        payments = Payments.query.options(
            load_only(Payments.PaymentID, Payments.Amount, Payments.PaymentDate, Payments.PaymentMethod, Payments.Reference, Payments.Status, Payments.SaleID),
            joinedload(Payments.sale).load_only(Sales.sale_id, Sales.price, Sales.paid, Sales.saleLocator, Sales.saleLink)
            .joinedload(Sales.customer).load_only(EventsUsers.FirstName, EventsUsers.LastName, EventsUsers.Email),
            joinedload(Payments.sale).joinedload(Sales.event_rel).load_only(Event.name)
        ).filter(Payments.Status == "pendiente").all()

        payments_list = []
        for payment in payments:

            lastName = payment.sale.customer.LastName if payment.sale.customer and payment.sale.customer.LastName else ''

            payments_list.append({
                "id": payment.PaymentID,
                "fullname": payment.sale.customer.FirstName + ' ' + lastName if payment.sale and payment.sale.customer else '',
                "email": payment.sale.customer.Email if payment.sale and payment.sale.customer else '',
                "event": payment.sale.event_rel.name if payment.sale and payment.sale.event_rel else '',
                "amount": round(payment.Amount/100, 2),
                "price": round(payment.sale.price/100, 2),
                "paid": round(payment.sale.paid/100, 2),
                "due": round((payment.sale.price - payment.sale.paid)/100, 2),
                "reference": payment.Reference,
                "date": payment.PaymentDate.strftime('%d/%m/%Y') if payment.PaymentDate else '',
                "payment_method": payment.PaymentMethod,
                "sale_id": payment.SaleID,
                "sale_price": payment.sale.price if payment.sale else 0,
                "sale_paid": payment.sale.paid if payment.sale else 0,
                "status": payment.Status,
                "locator": payment.sale.saleLocator if payment.sale else '',
            })

        return jsonify({"payments": payments_list, 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear evento: {e}")
        return jsonify({'message': 'Error al cargar los pagos', 'status': 'error'}), 500
    
@backend.route('/approve-abono', methods=['POST'])  # ruta del admin para aprobar un abono
@roles_required(allowed_roles=["admin"])
def approve_abono():
    try:
        user_id = get_jwt().get("id")

        # 1️⃣ Extraer datos del formulario
        payment_id = request.json.get('payment_id')
        received = request.json.get('received') * 100  # Convertir a centavos
        PaymentMethod = request.json.get('PaymentMethod')
        aprobacion = request.json.get('aprobacion')
        cancel_reservation = request.json.get('cancelReservation')

        if cancel_reservation is None:
            return jsonify({'message': 'Falta el campo cancel_reservation para el rechazo', 'status': 'error'}), 400
        
        if received is None or not isinstance(received, (int, float)) or received < 0:
            return jsonify({'message': 'El monto recibido no es válido', 'status': 'error'}), 400

        if not all([payment_id, PaymentMethod, aprobacion]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

        if aprobacion not in ['aprobado', 'rechazado']:
            return jsonify({'message': 'El estado de aprobación no es válido', 'status': 'error'}), 400

        # 2️⃣ Buscar el abono por su ID
        payment = Payments.query.options(
            joinedload(Payments.sale).joinedload(Sales.customer),
            joinedload(Payments.sale).joinedload(Sales.event_rel)
        ).filter(
            Payments.PaymentID == int(payment_id)
        ).one_or_none()

        if not payment:
            return jsonify({'message': 'No se encontró el abono asociado', 'status': 'error'}), 400

        if payment.Status == 'rechazado':
            return jsonify({'message': 'Este abono fue rechazado, esta acción es irreversible', 'status': 'error'}), 400

        if payment.sale.status == 'cancelado':
            return jsonify({'message': 'La venta está cancelada, no se pueden agregar abonos', 'status': 'error'}), 400
        
        # NOTA: Todos los valores ya están en centavos (int), pero usamos int() como medida defensiva
        total_due = int(payment.sale.price + payment.sale.fee - payment.sale.discount)
        total_after_payment = int(payment.sale.paid + received)

        if (total_after_payment - total_due) > 0:
            return jsonify({'message': 'El monto abonado excede el total de la venta. El abono no puede ser procesado.', 'status': 'error'}), 400

        # 3️⃣ Datos auxiliares
        customer = payment.sale.customer
        paymentDeadline = payment.sale.financiamiento_rel.Deadline if (payment.sale.financiamiento_rel and payment.sale.financiamiento_rel.Deadline) else ''
        event = payment.sale.event_rel

        Tickets = []
        ticket_ids = []
        raw_ticket_ids = payment.sale.ticket_ids or ''
        for tid in raw_ticket_ids.split('|'):
            tid_str = str(tid).strip()
            if not tid_str:
                continue
            try:
                ticket_ids.append(int(tid_str))
            except ValueError:
                logging.warning(f"Ignorando ticket_id inválido: {tid_str}")
                continue

        tickets_to_release = []
        tickets = Ticket.query.filter(Ticket.ticket_id.in_(ticket_ids)).all()

        if not tickets:
            return jsonify({'message': 'No se encontraron los tickets asociados a la venta', 'status': 'error'}), 400

        for ticket in tickets:
            t = {
                'ticket_id': ticket.ticket_id,
                'row': ticket.seat.row,
                'number': ticket.seat.number,
                'section': ticket.seat.section.name.replace('20_',' '),
                'event': ticket.price,
                'price': round(ticket.price / 100, 2)
            }
            Tickets.append(t)
            tickets_to_release.append(ticket.ticket_id_provider)

            if aprobacion == 'rechazado':
                if cancel_reservation:
                    if ticket.status in ['pagado por verificar', 'pendiente pago']:
                        ticket.status = 'disponible'
                        ticket.sale_id = None
                        ticket.fee = 0
                        ticket.expires_at = None
                        ticket.customer_id = None
                        ticket.blockedBy = None
                    else:
                        return jsonify({'message': f'El ticket {ticket.ticket_id} no está en un estado válido para ser liberado', 'status': 'error'}), 400

        qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={payment.sale.saleLink}'

        # 5️⃣ Rama de RECHAZO
        if aprobacion == 'rechazado':

            payment.Status = 'rechazado'
            payment.ApprovedBy = user_id
            payment.ApprovalDate = datetime.now()

            # ⚠️ Evitar autoflush prematuro que causa EOF detected
            with db.session.no_autoflush:
                log_for_rechazo = Logs(
                    UserID=user_id,
                    Type='abono',
                    Timestamp=datetime.now(),
                    Details=f"Abono de {received} rechazado para la venta {payment.sale.sale_id}",
                    SaleID=payment.sale.sale_id
                )
                db.session.add(log_for_rechazo)

                if cancel_reservation:
                    payment.sale.status = 'cancelado'

                    if event.from_api and tickets_to_release:

                        # 🔗 Llamar a Tickera para liberar los tickets bloqueados
                        try:
                            tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
                            tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')
                            url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/release-tickets"

                            logging.info("Liberando tickets en Tickera...")

                            payload = {
                                "event": event.event_id_provider,
                                "tickets": tickets_to_release,
                                "tickera_id": tickera_id,
                                "tickera_api_key": tickera_api_key
                            }

                            response_block = requests.post(url_block, json=payload, timeout=60)

                            if response_block.status_code != 200:
                                db.session.rollback()
                                return jsonify({
                                    "status": "error",
                                    "code": response_block.status_code,
                                    "message": response_block.json().get("message", "Error desconocido en Tickera")
                                }), response_block.status_code

                        except requests.exceptions.RequestException as e:
                            db.session.rollback()
                            logging.error(f"Error al liberar tickets en Tickera: {str(e)}")
                            return jsonify({"message": "Error al conectar con Tickera para liberar tickets"}), 502

                sale_data = {
                    'sale_id': payment.sale.sale_id,
                    'event': payment.sale.event_rel.name,
                    'venue': payment.sale.event_rel.venue.name,
                    'date': payment.sale.event_rel.date_string,
                    'hour': payment.sale.event_rel.hour_string,
                    'price': round(payment.sale.price / 100, 2),
                    'fee': round(payment.sale.fee / 100, 2),
                    'discount': round(payment.sale.discount / 100, 2),
                    'total_abono': round(received / 100, 2),
                    'due': round((payment.sale.price + payment.sale.fee - payment.sale.discount - received) / 100, 2),
                    'payment_method': PaymentMethod,
                    'payment_date': payment.PaymentDate if payment.PaymentDate else '',
                    'reference': payment.Reference if payment.Reference else '',
                    'link_reserva': qr_link,
                    'deadline_reserva': paymentDeadline,
                    'localizador': payment.sale.saleLocator,
                    'status': 'rechazado',
                    'title': 'Tu Abono no pudo ser procesado',
                    'subtitle': 'Por favor contacta a un administrador para más información'
                }

                if payment.sale.discount > 0:
                    discount_id = payment.sale.discount_ref
                    if discount_id:
                        discount = Discounts.query.filter(Discounts.DiscountID == discount_id).first()
                        if discount:
                            discount.UsedCount = (discount.UsedCount or 1) - 1

                utils.sendnotification_for_PaymentStatus(current_app.config, db, mail, customer, Tickets, sale_data)

            db.session.commit()
            return jsonify({'message': 'Abono rechazado exitosamente', 'status': 'ok'}), 200

        # 6️⃣ Rama de APROBACIÓN
        PaymentDate = request.json.get('PaymentDate')
        PaymentReference = request.json.get('PaymentReference')

        if not all([PaymentDate, PaymentReference]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400
        
        payment_date_str = PaymentDate

        # Convierte a objeto datetime
        if re.match(r'^\d{1,2}/\d{1,2}/\d{4}$', payment_date_str):
            payment_date = datetime.strptime(payment_date_str, "%d/%m/%Y").date()
        else:
            # Si viene en formato Y/m/d (o cualquier otro), no convertirlo aquí
            payment_date = payment_date_str
        
        # ⚠️ Evitar autoflush prematuro que causa EOF detected
        with db.session.no_autoflush:

            log_for_abono = Logs(
                UserID=user_id,
                Type='abono',
                Timestamp=datetime.now(),
                Details=f"Abono de {received} aprobado para la venta {payment.sale.sale_id}",
                SaleID=payment.sale.sale_id
            )
            db.session.add(log_for_abono)

            # Actualizar el payment
            payment.Status = 'aprobado'
            payment.ApprovedBy = user_id
            payment.ApprovalDate = datetime.now()
            payment.Amount = received
            payment.PaymentMethod = PaymentMethod
            payment.PaymentDate = payment_date
            payment.Reference = PaymentReference
            payment.sale.paid += received
            

            reserva_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={payment.sale.saleLink}'
            

            # Verificar si ya está completamente pagada
            # NOTA: Los valores están en centavos (integers), no necesitan rounding
            # Se compara: monto_pagado + descuento >= precio_total + fee
            if (payment.sale.paid + payment.sale.discount) >= (payment.sale.price + payment.sale.fee):

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
                    exchangeRate = int(raw_rate)
                except Exception:
                    db.session.rollback()
                    return jsonify({'message': 'Tasa de cambio en formato inválido', 'status': 'error'}), 500

                payment.sale.StatusFinanciamiento = 'pagado' #completamente pagado
                payment.sale.status = 'pagado' #cambiamos el estado de la venta a aprobado si ya se pagó todo
                # Normalizar y depurar ticket_ids: eliminar items vacíos y no numéricos
                raw_ticket_ids = payment.sale.ticket_ids or ''
                raw_list = raw_ticket_ids.split('|') if '|' in raw_ticket_ids else [raw_ticket_ids]
                ticket_ids = []
                for tid in raw_list:
                    tid_str = str(tid).strip()
                    if not tid_str:
                        continue
                    try:
                        ticket_ids.append(int(tid_str))
                    except ValueError:
                        logging.warning(f"Ignorando ticket_id inválido en sale.ticket_ids: {tid_str}")
                        continue

                total_fee= 0

                tickets_a_emitir = Ticket.query.filter(Ticket.ticket_id.in_(ticket_ids)).all()
                total_price = payment.sale.price
                total_price_addons = 0
                total_price_tickets = 0

                #chequeamos si hay addons
                add_ons = payment.sale.purchased_features
                add_ons_list = []
                if add_ons:
                    total_price_addons = 0
                    for addon in add_ons:
                        feature = addon.feature
                        if feature:
                            add_ons_list.append({
                                'FeatureName': feature.FeatureName,
                                'FeatureDescription': feature.FeatureDescription,
                                'FeaturePrice': round(addon.PurchaseAmount/100, 2),
                                'TotalPrice': round((addon.PurchaseAmount * addon.Quantity)/100, 2),
                                'Quantity': addon.Quantity
                            })
                            total_price_addons += addon.PurchaseAmount * addon.Quantity

                total_price_tickets = total_price - total_price_addons

                if not tickets_a_emitir:
                    return jsonify({'message': 'No se encontraron los tickets asociados a la venta', 'status': 'error'}), 400
                
                if len(tickets_a_emitir) != len(ticket_ids):
                    return jsonify({'message': 'No se encontraron todos los tickets asociados a la venta', 'status': 'error'}), 400
                
                # Validar que total_price no sea cero para evitar división por cero
                if not total_price or total_price == 0:
                    return jsonify({'message': 'Error: el precio total de la venta no puede ser cero', 'status': 'error'}), 400
                
                for ticket in tickets_a_emitir:

                    if not ticket:
                        return jsonify({'message': 'No se encontró el ticket asociado', 'status': 'error'}), 400
                    
                    discount = 0

                    if payment.sale.discount > 0:
                        proportion = ticket.price / total_price_tickets
                        discount = int(round(payment.sale.discount * proportion, 2))

                    
                    ticket.discount = discount
                    ticket.status = 'pagado'
                    ticket.availability_status = 'Listo para canjear'
                    ticket.emission_date = datetime.now().date()

                    log_for_emision = Logs(
                        UserID=user_id,
                        Type='emision de boleto',
                        Timestamp=datetime.now(),
                        Details=f"Emisión de boleto {ticket.ticket_id} para la venta {payment.sale.sale_id}",
                        SaleID=payment.sale.sale_id,
                        TicketID=ticket.ticket_id
                    )
                    db.session.add(log_for_emision)

                    serializer = current_app.config['serializer']
                    token = serializer.dumps({'ticket_id': ticket.ticket_id, 'sale_id': payment.sale.sale_id})
                    localizador = os.urandom(3).hex().upper()

                    ticket.saleLink = token
                    ticket.saleLocator = localizador

                    qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/tickets?query={token}'

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
                        'localizador': localizador
                    }

                    total_fee += ticket.fee if ticket.fee else 0

                    if event.type_of_event == 'espectaculo':
                        utils.sendqr_for_SuccessfulTicketEmission(current_app.config, db, mail, customer, sale_data, s3, ticket)

                IVA = current_app.config.get('IVA_PERCENTAGE', 0) / 100
                amount_no_IVA = int(round(received / (1 + (IVA)/100), 2))
                amount_IVA = received - amount_no_IVA
                if PaymentMethod.lower in utils.usd_payment_methods:
                    currency = 'usd'
                else:
                    currency = 'bsd'

                print(currency)

                sale_data = {
                    'sale_id': str(payment.sale.sale_id),
                    'event': payment.sale.event_rel.name,
                    'venue': payment.sale.event_rel.venue.name,
                    'date': payment.sale.event_rel.date_string,
                    'hour': payment.sale.event_rel.hour_string,
                    'price':  round(payment.sale.price / 100, 2),
                    'iva_amount': round(amount_IVA / 100, 2),
                    'net_amount': round(amount_no_IVA / 100, 2),
                    'total_abono': round(received / 100, 2),
                    'payment_method': PaymentMethod,
                    'payment_date': PaymentDate,
                    'reference': PaymentReference,
                    'link_reserva': reserva_link,
                    'localizador': payment.sale.saleLocator,
                    'exchange_rate_bsd': round(exchangeRate/100, 2),
                    'status': 'aprobado',
                    'title': 'Tu pago ha sido procesado exitosamente',
                    'subtitle': 'Gracias por tu compra, a continuación encontrarás los detalles de tu recibo',
                    'is_package_tour': payment.sale.event_rel.type_of_event == 'paquete_turistico',
                    'currency': currency,
                    'add_ons': add_ons_list
                }

                try:
                # Actualizar métricas del evento
                # NOTA: Solo se incrementan las métricas cuando la venta se completa por primera vez
                # gross_sales debe ser el precio total de la venta (sale.price), no el monto parcial recibido
                    stmt = (
                        update(Event)
                        .where(Event.event_id == int(event.event_id))
                        .values(
                            total_sales = func.coalesce(Event.total_sales, 0) + 1,
                            gross_sales = func.coalesce(Event.gross_sales, 0) + func.coalesce(payment.sale.price, 0),
                            total_fees  = func.coalesce(Event.total_fees, 0) + func.coalesce(total_fee, 0),
                            total_discounts = func.coalesce(Event.total_discounts, 0) + func.coalesce(payment.sale.discount, 0),
                            total_discounts_tickera = (
                                func.coalesce(Event.total_discounts_tickera, 0)
                                + (func.coalesce(Event.Fee, 0) * func.coalesce(payment.sale.discount, 0) / 100)
                            )
                        )
                        .returning(Event.event_id)  # opcional, útil para confirmar
                    )

                    db.session.execute(stmt)

                except Exception as e:
                    # En caso de cualquier error (ej. la tabla fue bloqueada brevemente)
                    logging.error(f"Error al actualizar métricas del evento: {e}")
                    db.session.rollback() 
                    return {"error": f"Fallo al actualizar DB: {e}"}, 500

                utils.sendnotification_for_CompletedPaymentStatus(current_app.config, db, mail, customer, Tickets, sale_data)
            else:

                sale_data = {
                    'sale_id': str(payment.sale.sale_id),
                    'event': payment.sale.event_rel.name,
                    'venue': payment.sale.event_rel.venue.name,
                    'date': payment.sale.event_rel.date_string,
                    'hour': payment.sale.event_rel.hour_string,
                    'price': round(payment.sale.price / 100, 2),
                    'fee': round(payment.sale.fee / 100, 2),
                    'discount': round(payment.sale.discount / 100, 2),
                    'total_abono': round(received / 100, 2),
                    'due': round((payment.sale.price + payment.sale.fee - payment.sale.discount - received) / 100, 2),
                    'payment_method': PaymentMethod,
                    'payment_date': PaymentDate,
                    'reference': PaymentReference,
                    'link_reserva': reserva_link,
                    'deadline_reserva': paymentDeadline,
                    'localizador': payment.sale.saleLocator,
                    'status': 'aprobado',
                    'title': 'Tu Abono ha sido procesado exitosamente',
                    'subtitle': 'Gracias por tu compra, a continuación encontrarás los detalles de tu abono'
                }

                utils.sendnotification_for_PaymentStatus(current_app.config, db, mail, customer, Tickets, sale_data)

        db.session.commit()

        return jsonify({'message': 'Abono registrado exitosamente', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al registrar abono: {e}")
        return jsonify({'message': 'Error al registrar abono', 'status': 'error'}), 500

@backend.route('/refund', methods=['POST'])  # ruta del admin para procesar reembolsos
@roles_required(allowed_roles=["admin"])
def refund():
    try:
        user_id = get_jwt().get("id")

        # Extraer datos del formulario (mismos parámetros que approve-abono en rama de rechazo)
        sale_id = request.json.get('sale_id')
        refunded = request.json.get('received', 0) * 100  # Convertir a centavos
        refunded_fee = request.json.get('refunded_fee', False)
        PaymentMethod = request.json.get('PaymentMethod', 'N/A')
        PaymentDate = request.json.get('PaymentDate', 'N/A')
        PaymentReference = request.json.get('PaymentReference', 'N/A')

        if not sale_id:
            return jsonify({'message': 'Falta el id de la venta', 'status': 'error'}), 400

        # Buscar la venta por su ID
        sale = Sales.query.options(
            joinedload(Sales.customer),
            joinedload(Sales.event_rel)
        ).filter(
            Sales.sale_id == int(sale_id)
        ).one_or_none()

        if not sale:
            return jsonify({'message': 'No se encontró la venta asociada', 'status': 'error'}), 400

        if sale.status == 'cancelado':
            return jsonify({'message': 'La venta ya está cancelada', 'status': 'error'}), 400

        customer = sale.customer
        event = sale.event_rel

        # Obtener tickets asociados
        Tickets = []
        ticket_ids = []
        raw_ticket_ids = sale.ticket_ids or ''
        for tid in raw_ticket_ids.split('|'):
            tid_str = str(tid).strip()
            if not tid_str:
                continue
            try:
                ticket_ids.append(int(tid_str))
            except ValueError:
                logging.warning(f"Ignorando ticket_id inválido: {tid_str}")
                continue

        tickets_to_release = []
        tickets = Ticket.query.filter(Ticket.ticket_id.in_(ticket_ids)).all()

        if not tickets:
            return jsonify({'message': 'No se encontraron los tickets asociados a la venta', 'status': 'error'}), 400

        for ticket in tickets:
            t = {
                'ticket_id': ticket.ticket_id,
                'row': ticket.seat.row,
                'number': ticket.seat.number,
                'section': ticket.seat.section.name.replace('20_', ' '),
                'price': round(ticket.price / 100, 2)
            }
            Tickets.append(t)
            tickets_to_release.append(ticket.ticket_id_provider)

            # Liberar el ticket
            ticket.status = 'disponible'
            ticket.sale_id = None
            ticket.fee = 0
            ticket.discount = 0
            ticket.expires_at = None
            ticket.customer_id = None
            ticket.blockedBy = None
            ticket.saleLink = ''
            ticket.saleLocator = ''
            ticket.QRlink = ''
            ticket.availability_status = ''

        # Marcar la venta como reembolsado
        sale.status = 'reembolsado'
        sale.paid = 0
        sale.StatusFinanciamiento = 'reembolsado'

        #creamos el registro de pago de reembolso
        new_payment_entry = Payments(
            SaleID=sale.sale_id,
            Amount= -int(refunded),
            PaymentMethod=PaymentMethod,
            PaymentDate=datetime.strptime(PaymentDate, "%d/%m/%Y").date() if re.match(r'^\d{1,2}/\d{1,2}/\d{4}$', PaymentDate) else PaymentDate,
            Reference=PaymentReference,
            Status='reembolsado',
            CreatedBy=user_id,
            ApprovedBy=user_id,
            ApprovalDate=datetime.now() 
        )
        db.session.add(new_payment_entry)

        # Si el evento es de API, liberar los tickets en Tickera
        if event and event.from_api and tickets_to_release:
            try:
                tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
                tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')
                url_release = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/release-tickets"

                logging.info("Liberando tickets en Tickera para reembolso...")

                payload = {
                    "event": event.event_id_provider,
                    "tickets": tickets_to_release,
                    "tickera_id": tickera_id,
                    "tickera_api_key": tickera_api_key
                }

                response_release = requests.post(url_release, json=payload, timeout=60)

                if response_release.status_code != 200:
                    db.session.rollback()
                    return jsonify({
                        "status": "error",
                        "code": response_release.status_code,
                        "message": response_release.json().get("message", "Error desconocido en Tickera")
                    }), response_release.status_code

            except requests.exceptions.RequestException as e:
                db.session.rollback()
                logging.error(f"Error al liberar tickets en Tickera: {str(e)}")
                return jsonify({"message": "Error al conectar con Tickera para liberar tickets"}), 502

        # Registrar el log de reembolso
        log_for_refund = Logs(
            UserID=user_id,
            Type='reembolso',
            Timestamp=datetime.now(),
            Details=f"Reembolso procesado para la venta {sale.sale_id} del usuario {customer.Email if customer else 'N/A'}",
            SaleID=sale.sale_id
        )
        db.session.add(log_for_refund)

        # Preparar datos para notificaciones
        qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={sale.saleLink}' if sale.saleLink else ''

        sale_data = {
            'sale_id': sale.sale_id,
            'event': event.name if event else 'N/A',
            'venue': event.venue.name if event and event.venue else 'N/A',
            'date': event.date_string if event else 'N/A',
            'hour': event.hour_string if event else 'N/A',
            'price': round(sale.price / 100, 2),
            'fee': round(sale.fee / 100, 2),
            'discount': round(sale.discount / 100, 2),
            'total_abono': round(refunded / 100, 2),
            'payment_method': PaymentMethod,
            'link_reserva': qr_link,
            'localizador': sale.saleLocator,
            'status': 'reembolsado'
        }

        try:
        # Actualizar métricas del evento
        # NOTA: Solo se incrementan las métricas cuando la venta se completa por primera vez
        # gross_sales debe ser el precio total de la venta (sale.price), no el monto parcial recibido
            stmt = (
                update(Event)
                .where(Event.event_id == int(event.event_id))
                .values(
                    total_sales = func.coalesce(Event.total_sales, 0) - 1,
                    gross_sales = func.coalesce(Event.gross_sales, 0) - refunded,
                    total_discounts = func.coalesce(Event.total_discounts, 0) - func.coalesce(sale.discount, 0),
                    total_fees  = (func.coalesce(Event.total_fees, 0) - func.coalesce(sale.fee, 0)) if refunded_fee else func.coalesce(Event.total_fees, 0),
                    total_discounts_tickera = (
                        func.coalesce(Event.total_discounts_tickera, 0)
                        - (func.coalesce(Event.Fee, 0) * func.coalesce(sale.discount, 0) / 100)
                    ) if refunded_fee else func.coalesce(Event.total_discounts_tickera, 0)
                )
                .returning(Event.event_id)  # opcional, útil para confirmar
            )
            db.session.execute(stmt)

        except Exception as e:
            # En caso de cualquier error (ej. la tabla fue bloqueada brevemente)
            logging.error(f"Error al actualizar métricas del evento: {e}")
            db.session.rollback() 
            return {"error": f"Fallo al actualizar DB: {e}"}, 500

        # Enviar notificación al usuario
        if customer:
            try:
                recipient = customer.Email
                subject = f'Reembolso procesado para {sale_data["event"]} - Fiesta Ticket'

                msg = Message(subject, sender=current_app.config["MAIL_USERNAME"], recipients=[recipient])
                msg_html = render_template('refund_notification.html', Tickets=Tickets, sale_data=sale_data)
                msg.html = msg_html

                mail.send(msg)
            except Exception as e:
                logging.error(f"Error enviando email al usuario: {e}")

        # Enviar notificación a los administradores
        try:
            admin_subject = f'Reembolso procesado para {sale_data["event"]} - Fiesta Ticket'
            
            admins = EventsUsers.query.filter(EventsUsers.role.in_(["admin", "tiquetero"])).all()
            admin_recipients = [admin.Email for admin in admins]

            message_admin = (
                f'🔄 **REEMBOLSO PROCESADO** 🔄\n\n'
                f'Hola Equipo,\n\n'
                f'Se ha procesado un **reembolso** para la venta ID {sale.sale_id} '
                f'del usuario **{customer.Email if customer else "N/A"}** para el evento **{sale_data["event"]}**.\n\n'
                f'---\n'
                f'## 👤 Detalles del Usuario\n'
                f'- **Nombre Completo:** {customer.FirstName if customer else "N/A"} {customer.LastName if customer else ""}\n'
                f'- **Email:** {customer.Email if customer else "N/A"}\n'
                f'- **Teléfono:** {customer.PhoneNumber if customer else "No registrado"}\n'
                f'- **ID de Cliente:** {customer.CustomerID if customer else "N/A"}\n'
                f'---\n'
                f'## 🎫 Detalles de la Venta\n'
                f'- **Evento:** {sale_data["event"]} ({sale_data["venue"]})\n'
                f'- **Fecha y Hora:** {sale_data["date"]} a las {sale_data["hour"]}\n'
                f'- **Localizador:** {sale_data.get("localizador", "N/A")}\n'
                f'- **Cantidad de Boletos:** {len(Tickets)}\n\n'
                f'---\n'
                f'## 🎟️ Boletos Afectados ({len(Tickets)} en total)\n'
            )

            if Tickets:
                for i, ticket in enumerate(Tickets, 1):
                    detalle_ticket = (
                        f'    {i}. ID: {ticket["ticket_id"]} | '
                        f'Sección: {ticket["section"].upper()} | '
                        f'Fila/Número: {ticket["row"]}/{ticket["number"]} | '
                        f'Precio: ${ticket["price"]}\n'
                    )
                    message_admin += detalle_ticket

            message_admin += (
                f'\n---\n'
                f'## 💰 Detalles Financieros\n'
                f'- **Subtotal:** ${sale_data.get("price", "N/A")}\n'
                f'- **Fee:** ${sale_data.get("fee", "N/A")}\n'
                f'- **Descuento:** ${sale_data.get("discount", "N/A")}\n'
                f'- **Total:** ${sale_data.get("price", 0) + sale_data.get("fee", 0) - sale_data.get("discount", 0)}\n\n'
                f'---\n'
                f'## 📝 Información Importante\n'
                f'Todos los boletos y reservas del usuario para este evento **YA NO TIENEN VALIDEZ**.\n'
                f'El usuario ha sido notificado de esta acción.\n\n'
                f'Gracias,\n'
                f'**Equipo de Fiesta Ticket**\n'
            )

            msg_admin = Message(admin_subject, sender=current_app.config["MAIL_USERNAME"], recipients=admin_recipients)
            msg_admin.body = message_admin

            mail.send(msg_admin)
        except Exception as e:
            logging.error(f"Error enviando email a administradores: {e}")

        db.session.commit()

        return jsonify({'message': 'Reembolso procesado exitosamente', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al procesar reembolso: {e}")
        return jsonify({'message': 'Error al procesar reembolso', 'status': 'error'}), 500
    
@backend.route('/cancel-reservation', methods=['GET']) #para cancelar una reserva
@roles_required(allowed_roles=["admin"])
def cancel_reservation():
    try:
        user_id = get_jwt().get("id")
        user_role = get_jwt().get("role")

        # 1. Extraer datos del formulario
        sale_id = request.args.get('query', '')

        if not all([sale_id]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

        # Modificar Ticket
        sale = Sales.query.filter(
            and_(Sales.sale_id == int(sale_id))
        ).one_or_none()

        if not sale:
            return jsonify({'message': f'No se encontró la venta', 'status': 'error'}), 400
        
        if user_role != 'admin':
            if sale.user_id != user_id:
                return jsonify({'message': f'No tienes permisos para cancelar esta venta', 'status': 'error'}), 400

        if sale.status == 'cancelado':
            return jsonify({'message': f"Esta venta ya se encuentra cancelada", 'status': 'error'}), 400

        sale.status = 'cancelado'

        if sale.event_rel:
            # Actualizar el estado de los tickets asociados a "disponible"
            ticket_ids = sale.ticket_ids.split('|') if '|' in sale.ticket_ids else [sale.ticket_ids]
            for ticket_id in ticket_ids:
                
                if ticket_id == '':
                    continue
                
                ticket = Ticket.query.get(int(ticket_id))

                if not ticket:
                    return jsonify({'message': 'No se encontró el ticket asociado', 'status': 'error'}), 400

                ticket.status = 'disponible'
                ticket.availability_status = ''
                ticket.customer_id = None
                ticket.fee = 0
                ticket.discount = 0
                ticket.saleLink = ''
                ticket.saleLocator = ''
                ticket.QRlink = ''
                ticket.sale_id = None

        eventName = sale.event_rel.name if sale.event_rel else 'Evento Personalizado'

        log_for_block = Logs(
            UserID=user_id,
            Type='venta cancelada',
            Timestamp=datetime.now(),
            Details=f"Se ha cancelado la venta de ID {sale_id} (del usuario {sale.customer.Email}) del evento {eventName}",
        ) 
        db.session.add(log_for_block)

        db.session.commit()

        return jsonify({'message': 'Reserva cancelada exitosamente', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al dcancelar reserva: {e}")
        return jsonify({'message': 'Error al cancelar reserva', 'status': 'error'}), 500

@backend.route('/upgrade-reservation', methods=['POST'])  # ruta para hacer upgrades a reservas existentes
@roles_required(allowed_roles=["admin"])
def upgrade_reservation():
    try:
        user_id = get_jwt().get("id")

        # Extraer datos del formulario
        sale_id = request.json.get('sale_id')
        new_ticket_ids = request.json.get('new_ticket_ids', [])  # IDs de nuevos tickets
        addon_ids = request.json.get('addon_ids', [])  # Lista de {feature_id, quantity}
        additional_payment = request.json.get('additional_payment', 0) * 100  # Dinero adicional en centavos
        payment_method = request.json.get('payment_method', 'efectivo')
        payment_reference = request.json.get('payment_reference', '')

        if not sale_id:
            return jsonify({'message': 'Falta el sale_id', 'status': 'error'}), 400

        # Buscar la venta
        sale = Sales.query.options(
            joinedload(Sales.customer),
            joinedload(Sales.event_rel).joinedload(Event.venue)
        ).filter(
            Sales.sale_id == int(sale_id)
        ).one_or_none()

        if not sale:
            return jsonify({'message': 'No se encontró la venta asociada', 'status': 'error'}), 400

        if sale.status == 'cancelado':
            return jsonify({'message': 'La venta está cancelada, no se puede hacer upgrade', 'status': 'error'}), 400

        customer = sale.customer
        event = sale.event_rel
        old_price = sale.price
        old_ticket_ids_str = sale.ticket_ids or ''

        # Parse old ticket IDs
        old_ticket_ids = []
        for tid in old_ticket_ids_str.split('|'):
            tid_str = str(tid).strip()
            if not tid_str:
                continue
            try:
                old_ticket_ids.append(int(tid_str))
            except ValueError:
                logging.warning(f"Ignorando ticket_id inválido: {tid_str}")
                continue

        # Manejar cambio de tickets (si se proporcionan nuevos tickets)
        tickets_to_release_api = []
        tickets_to_block_api = []
        new_price = old_price

        if new_ticket_ids:
            # Liberar los tickets antiguos
            old_tickets = Ticket.query.filter(Ticket.ticket_id.in_(old_ticket_ids)).all()
            for ticket in old_tickets:
                if event and event.from_api:
                    tickets_to_release_api.append(ticket.ticket_id_provider)
                
                ticket.status = 'disponible'
                ticket.sale_id = None
                ticket.fee = 0
                ticket.discount = 0
                ticket.expires_at = None
                ticket.customer_id = None
                ticket.blockedBy = None
                ticket.saleLink = ''
                ticket.saleLocator = ''
                ticket.QRlink = ''
                ticket.availability_status = ''

            # Asignar los nuevos tickets
            new_tickets = Ticket.query.filter(Ticket.ticket_id.in_(new_ticket_ids)).all()
            
            if len(new_tickets) != len(new_ticket_ids):
                db.session.rollback()
                return jsonify({'message': 'Algunos tickets no fueron encontrados', 'status': 'error'}), 400

            new_price = 0
            new_ticket_ids_validated = []
            
            for ticket in new_tickets:
                if ticket.status != 'disponible':
                    db.session.rollback()
                    return jsonify({'message': f'El ticket {ticket.ticket_id} no está disponible', 'status': 'error'}), 400
                
                ticket.status = 'pagado por verificar' if sale.status in ['pendiente pago', 'pagado por verificar'] else 'pagado'
                ticket.sale_id = sale.sale_id
                ticket.customer_id = customer.CustomerID if customer else None
                ticket.fee = event.Fee if event and event.Fee else 0
                new_price += ticket.price
                new_ticket_ids_validated.append(str(ticket.ticket_id))

                if event and event.from_api:
                    tickets_to_block_api.append(ticket.ticket_id_provider)

            # Actualizar los ticket_ids en la venta
            sale.ticket_ids = '|'.join(new_ticket_ids_validated)

        # Manejar addons
        addon_total = 0
        if addon_ids:
            for addon_data in addon_ids:
                feature_id = addon_data.get('feature_id')
                quantity = addon_data.get('quantity', 1)
                
                if not feature_id or quantity <= 0:
                    continue

                feature = AdditionalFeatures.query.filter(
                    AdditionalFeatures.FeatureID == int(feature_id),
                    AdditionalFeatures.Active == True
                ).one_or_none()

                if not feature:
                    db.session.rollback()
                    return jsonify({'message': f'El addon {feature_id} no está disponible', 'status': 'error'}), 400

                # Verificar si ya existe este addon para esta venta
                existing_purchase = PurchasedFeatures.query.filter(
                    PurchasedFeatures.SaleID == sale.sale_id,
                    PurchasedFeatures.FeatureID == feature.FeatureID
                ).one_or_none()

                if existing_purchase:
                    # Actualizar cantidad
                    existing_purchase.Quantity += quantity
                    existing_purchase.PurchaseAmount = feature.FeaturePrice
                else:
                    # Crear nuevo registro
                    purchased_feature = PurchasedFeatures(
                        SaleID=sale.sale_id,
                        FeatureID=feature.FeatureID,
                        Quantity=quantity,
                        PurchaseAmount=feature.FeaturePrice
                    )
                    db.session.add(purchased_feature)

                addon_total += feature.FeaturePrice * quantity

        # Calcular nuevo precio total
        if new_ticket_ids:
            sale.price = new_price + addon_total
        else:
            sale.price += addon_total

        price_difference = sale.price - old_price

        # Manejar pago adicional
        if additional_payment > 0:
            # Crear registro de pago
            new_payment = Payments(
                SaleID=sale.sale_id,
                Amount=additional_payment,
                PaymentMethod=payment_method,
                Reference=payment_reference,
                Status='aprobado',
                PaymentDate=datetime.now().date(),
                CreatedBy=user_id,
                ApprovedBy=user_id,
                ApprovalDate=datetime.now()
            )
            db.session.add(new_payment)
            sale.paid += additional_payment

        # Llamadas a API si es necesario
        if event and event.from_api:
            tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
            tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

            # Liberar tickets antiguos
            if tickets_to_release_api:
                try:
                    url_release = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/release-tickets"
                    logging.info("Liberando tickets antiguos en Tickera para upgrade...")

                    payload_release = {
                        "event": event.event_id_provider,
                        "tickets": tickets_to_release_api,
                        "tickera_id": tickera_id,
                        "tickera_api_key": tickera_api_key
                    }

                    response_release = requests.post(url_release, json=payload_release, timeout=60)

                    if response_release.status_code != 200:
                        db.session.rollback()
                        return jsonify({
                            "status": "error",
                            "code": response_release.status_code,
                            "message": response_release.json().get("message", "Error liberando tickets en Tickera")
                        }), response_release.status_code

                except requests.exceptions.RequestException as e:
                    db.session.rollback()
                    logging.error(f"Error al liberar tickets en Tickera: {str(e)}")
                    return jsonify({"message": "Error al conectar con Tickera para liberar tickets"}), 502

            # Bloquear nuevos tickets
            if tickets_to_block_api:
                try:
                    url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/block-tickets"
                    logging.info("Bloqueando nuevos tickets en Tickera para upgrade...")

                    payload_block = {
                        "event": event.event_id_provider,
                        "tickets": tickets_to_block_api,
                        "tickera_id": tickera_id,
                        "tickera_api_key": tickera_api_key
                    }

                    response_block = requests.post(url_block, json=payload_block, timeout=60)

                    if response_block.status_code != 200:
                        db.session.rollback()
                        return jsonify({
                            "status": "error",
                            "code": response_block.status_code,
                            "message": response_block.json().get("message", "Error bloqueando tickets en Tickera")
                        }), response_block.status_code

                except requests.exceptions.RequestException as e:
                    db.session.rollback()
                    logging.error(f"Error al bloquear tickets en Tickera: {str(e)}")
                    return jsonify({"message": "Error al conectar con Tickera para bloquear tickets"}), 502

        # Si la venta ya estaba pagada, emitir los nuevos boletos
        if sale.status == 'pagado' and new_ticket_ids:
            serializer = current_app.config['serializer']
            
            for ticket_id in new_ticket_ids:
                ticket = Ticket.query.get(int(ticket_id))
                if ticket:
                    ticket.status = 'pagado'
                    ticket.availability_status = 'Listo para canjear'
                    ticket.emission_date = datetime.now().date()

                    token = serializer.dumps({'ticket_id': ticket.ticket_id, 'sale_id': sale.sale_id})
                    localizador = os.urandom(3).hex().upper()

                    ticket.saleLink = token
                    ticket.saleLocator = localizador

                    qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/tickets?query={token}'

                    sale_data = {
                        'row': ticket.seat.row,
                        'number': ticket.seat.number,
                        'section': ticket.seat.section.name,
                        'event': event.name,
                        'venue': event.venue.name,
                        'date': event.date_string,
                        'hour': event.hour_string,
                        'price': round(ticket.price / 100, 2),
                        'discount': round(ticket.discount / 100, 2),
                        'fee': round(ticket.fee / 100, 2),
                        'total': round((ticket.price + ticket.fee - ticket.discount) / 100, 2),
                        'link_reserva': qr_link,
                        'localizador': localizador
                    }

                    if event.type_of_event == 'espectaculo':
                        utils.sendqr_for_SuccessfulTicketEmission(current_app.config, db, mail, customer, sale_data, s3, ticket)

        # Registrar log
        log_for_upgrade = Logs(
            UserID=user_id,
            Type='upgrade de reserva',
            Timestamp=datetime.now(),
            Details=f"Upgrade procesado para la venta {sale.sale_id}. Precio anterior: {old_price/100}, nuevo precio: {sale.price/100}",
            SaleID=sale.sale_id
        )
        db.session.add(log_for_upgrade)

        # Preparar datos para notificaciones
        new_tickets_data = []
        if new_ticket_ids:
            for ticket_id in new_ticket_ids:
                ticket = Ticket.query.get(int(ticket_id))
                if ticket:
                    new_tickets_data.append({
                        'ticket_id': ticket.ticket_id,
                        'row': ticket.seat.row,
                        'number': ticket.seat.number,
                        'section': ticket.seat.section.name,
                        'price': round(ticket.price / 100, 2)
                    })

        addons_data = []
        if addon_ids:
            purchased_features = PurchasedFeatures.query.filter(PurchasedFeatures.SaleID == sale.sale_id).all()
            for pf in purchased_features:
                feature = pf.feature
                if feature:
                    addons_data.append({
                        'FeatureName': feature.FeatureName,
                        'FeatureDescription': feature.FeatureDescription,
                        'FeaturePrice': round(pf.PurchaseAmount / 100, 2),
                        'Quantity': pf.Quantity,
                        'TotalPrice': round((pf.PurchaseAmount * pf.Quantity) / 100, 2)
                    })

        sale_data = {
            'sale_id': sale.sale_id,
            'event': event.name if event else 'N/A',
            'venue': event.venue.name if event and event.venue else 'N/A',
            'date': event.date_string if event else 'N/A',
            'hour': event.hour_string if event else 'N/A',
            'old_price': round(old_price / 100, 2),
            'new_price': round(sale.price / 100, 2),
            'price_difference': round(price_difference / 100, 2),
            'additional_payment': round(additional_payment / 100, 2),
            'localizador': sale.saleLocator,
            'new_tickets': new_tickets_data,
            'addons': addons_data
        }

        # Enviar notificación al usuario
        if customer:
            try:
                recipient = customer.Email
                subject = f'Upgrade de reserva para {sale_data["event"]} - Fiesta Ticket'

                msg = Message(subject, sender=current_app.config["MAIL_USERNAME"], recipients=[recipient])
                msg_html = render_template('upgrade_notification.html', sale_data=sale_data)
                msg.html = msg_html

                mail.send(msg)
            except Exception as e:
                logging.error(f"Error enviando email al usuario: {e}")

        # Enviar notificación a los administradores
        try:
            admin_subject = f'Upgrade de reserva procesado para {sale_data["event"]} - Fiesta Ticket'
            
            admins = EventsUsers.query.filter(EventsUsers.role.in_(["admin", "tiquetero"])).all()
            admin_recipients = [admin.Email for admin in admins]

            message_admin = (
                f'⬆️ **UPGRADE DE RESERVA PROCESADO** ⬆️\n\n'
                f'Hola Equipo,\n\n'
                f'Se ha procesado un **upgrade** para la venta ID {sale.sale_id} '
                f'del usuario **{customer.Email if customer else "N/A"}** para el evento **{sale_data["event"]}**.\n\n'
                f'---\n'
                f'## 👤 Detalles del Usuario\n'
                f'- **Nombre Completo:** {customer.FirstName if customer else "N/A"} {customer.LastName if customer else ""}\n'
                f'- **Email:** {customer.Email if customer else "N/A"}\n'
                f'- **ID de Cliente:** {customer.CustomerID if customer else "N/A"}\n'
                f'---\n'
                f'## 🎫 Detalles del Upgrade\n'
                f'- **Evento:** {sale_data["event"]} ({sale_data["venue"]})\n'
                f'- **Localizador:** {sale_data.get("localizador", "N/A")}\n'
                f'- **Precio Anterior:** ${sale_data["old_price"]}\n'
                f'- **Precio Nuevo:** ${sale_data["new_price"]}\n'
                f'- **Diferencia:** ${sale_data["price_difference"]}\n'
                f'- **Pago Adicional:** ${sale_data["additional_payment"]}\n\n'
            )

            if new_tickets_data:
                message_admin += f'---\n## 🎟️ Nuevos Boletos ({len(new_tickets_data)} en total)\n'
                for i, ticket in enumerate(new_tickets_data, 1):
                    message_admin += (
                        f'    {i}. ID: {ticket["ticket_id"]} | '
                        f'Sección: {ticket["section"].upper()} | '
                        f'Fila/Número: {ticket["row"]}/{ticket["number"]} | '
                        f'Precio: ${ticket["price"]}\n'
                    )

            if addons_data:
                message_admin += f'\n---\n## ➕ Addons Agregados ({len(addons_data)} en total)\n'
                for i, addon in enumerate(addons_data, 1):
                    message_admin += (
                        f'    {i}. {addon["FeatureName"]} | '
                        f'Cantidad: {addon["Quantity"]} | '
                        f'Precio Unitario: ${addon["FeaturePrice"]} | '
                        f'Total: ${addon["TotalPrice"]}\n'
                    )

            message_admin += (
                f'\n---\n'
                f'Gracias,\n'
                f'**Equipo de Fiesta Ticket**\n'
            )

            msg_admin = Message(admin_subject, sender=current_app.config["MAIL_USERNAME"], recipients=admin_recipients)
            msg_admin.body = message_admin

            mail.send(msg_admin)
        except Exception as e:
            logging.error(f"Error enviando email a administradores: {e}")

        db.session.commit()

        return jsonify({'message': 'Upgrade procesado exitosamente', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al procesar upgrade: {e}")
        return jsonify({'message': 'Error al procesar upgrade', 'status': 'error'}), 500
    
@backend.route('/modify-reservation', methods=['POST']) #para modificarr una reserva (nombre o email)
@roles_required(allowed_roles=["admin", "tiquetero"])
def modify_reservation():
    try:
        user_id = get_jwt().get("id")
        user_role = get_jwt().get("role")
        today = datetime.utcnow().date()

        # 1. Extraer datos del formulario
        sale_id = request.args.get('query', '')
        new_name = request.json.get('name', '')
        new_email = request.json.get('email', '')

        if not all([sale_id, new_email, new_email]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400
        
        new_email=new_email.lower().strip()
        
        if not utils.email_pattern.match(new_email):
            return jsonify(message='Direccion de correo electronico invalida'), 400

        # Modificar Ticket
        sale = Sales.query.filter(
            and_(Sales.sale_id == int(sale_id))
        ).one_or_none()

        if not sale:
            return jsonify({'message': f'No se encontró la venta', 'status': 'error'}), 400
        
        if user_role != 'admin':
            if sale.user_id != user_id:
                return jsonify({'message': f'No tienes permisos para cancelar esta venta', 'status': 'error'}), 400

        if sale.status == 'cancelado':
            return jsonify({'message': f"Esta venta se encuentra cancelada", 'status': 'error'}), 400
        
        if new_email == sale.customer.Email:
            sale.customer.FirstName = new_name.split(' ')[0] if ' ' in new_name else new_name
            sale.customer.LastName = new_name.split(' ')[1] if ' ' in new_name else ''

        if new_email != sale.customer.Email:
            serializer = current_app.config['serializer']
            token = serializer.dumps({'user_id':  sale.customer.CustomerID, 'sale_id': sale.sale_id})
            localizador = os.urandom(3).hex().upper()

            sale.saleLink = token
            sale.saleLocator = localizador
            
            customer = EventsUsers.query.filter_by(Email=new_email).one_or_none()

            if customer is None:
                customer = EventsUsers(
                    FirstName = new_name.split(' ')[0] if ' ' in new_name else new_name,
                    LastName = new_name.split(' ')[1] if ' ' in new_name else '',
                    Email=new_email,
                    role='passive_customer',
                    status='unverified',
                    CreatedBy=user_id,
                )
                db.session.add(customer)
                db.session.flush()  # para obtener customer_id

            sale.user_id = customer.CustomerID
            eventName = sale.event_rel.name if sale.event_rel else 'Evento Personalizado'

            # Actualizar el estado de los tickets asociados si estos ya fueron emitidos

            selectedSeats = []
            
            ticket_ids = sale.ticket_ids.split('|') if '|' in sale.ticket_ids else [sale.ticket_ids]
            for ticket_id in ticket_ids:

                if ticket_id == '':
                    continue

                ticket = Ticket.query.get(int(ticket_id))

                if not ticket:
                    return jsonify({'message': 'No se encontró el ticket asociado', 'status': 'error'}), 400
            
                ticket_dict = {
                    "section": ticket.seat.section.name,
                    "row": ticket.seat.row,
                    "number": ticket.seat.number,
                    "price": ticket.price
                }
                
                selectedSeats.append(ticket_dict)
                
                if sale.status == 'pagado':

                    serializer = current_app.config['serializer']
                    token = serializer.dumps({'ticket_id': ticket.ticket_id, 'sale_id': sale.sale_id})
                    localizador = os.urandom(3).hex().upper()

                    ticket.saleLink = token
                    ticket.saleLocator = localizador
                    ticket.emission_date = today

                    qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/tickets?query={token}'

                    sale_data = {
                        'row': ticket.seat.row,
                        'number': ticket.seat.number,
                        'section': ticket.seat.section.name,
                        'event': ticket.event.name,
                        'venue': ticket.event.venue.name,
                        'date': ticket.event.date_string,
                        'hour': ticket.event.hour_string,
                        'price': round(ticket.price/100, 2),
                        'discount': round(ticket.discount/100, 2),
                        'fee': round(ticket.fee/100, 2),
                        'total': round((ticket.price + ticket.fee - ticket.discount)/100, 2),
                        'link_reserva': qr_link,
                        'localizador': localizador
                    }

                    utils.sendqr_for_SuccessfulTicketEmission(current_app.config, db, mail, customer, sale_data, s3, ticket)

            serializer = current_app.config['serializer']
            token = serializer.dumps({'user_id': customer.CustomerID, 'sale_id': sale.sale_id})
            localizador = os.urandom(3).hex().upper()

            sale.saleLink = token
            sale.saleLocator = localizador

            qr_link = f'{current_app.config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={token}'

            DeadlineReserva = sale.financiamiento_rel.Deadline if sale.financiamiento_rel else None
            FinanciamientoType = sale.financiamiento_rel.Type if sale.financiamiento_rel else "decontado"

            sale_data = {
                'sale_id': sale.sale_id,
                'event': sale.event_rel.name,
                'venue': sale.event_rel.venue.name,
                'date': sale.event_rel.date_string,
                'hour': sale.event_rel.hour_string,
                'tickets': selectedSeats,
                'total_price': round(sale.price/100, 2) ,
                'paid': round(sale.paid/100, 2),
                'discount': round(sale.discount/100, 2),
                'fee': round(sale.fee/100, 2),
                'due': round((sale.price + sale.fee - sale.paid - sale.discount)/100, 2),
                'link_reserva': qr_link,
                'deadline_reserva': DeadlineReserva,
                'localizador': localizador
            }

            utils.sendqr_for_ConfirmedReservationOrFin(FinanciamientoType, current_app.config, db, mail, customer, selectedSeats, sale_data)

        log_for_block = Logs(
            UserID=user_id,
            Type='se ha modificado una reserva',
            Timestamp=datetime.now(),
            Details=f"SLa reserva de ID {sale_id} (del usuario {sale.customer.Email}) del evento {eventName} ha sido modificada",
        ) 
        db.session.add(log_for_block)

        db.session.commit()

        return jsonify({'message': 'Reserva modificada exitosamente', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al modificar reserva: {e}")
        return jsonify({'message': 'Error al modificar reserva', 'status': 'error'}), 500
    
@backend.route('/resend-ticket', methods=['GET'])  #ruta del admin para aprobar un abono
@roles_required(allowed_roles=["admin", "tiquetero"])
def resend_ticket():
    try:

        # 1. Extraer datos del formulario
        ticketId = request.args.get('query')

        if not all([ticketId]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

         # Buscar el abono por su ID
        
        ticket = Ticket.query.filter(
            and_(
                Ticket.ticket_id == int(ticketId),
            )
        ).one_or_none()


        if not ticket:
            return jsonify({'message': 'No se encontró el ticket asociado', 'status': 'error'}), 40
        
        if not ticket.saleLink:
            return jsonify({'message': 'El ticket no se encuentra emitido', 'status': 'error'}), 400
        
        if not ticket.customer:
            return jsonify({'message': 'No se encontró el cliente asociado', 'status': 'error'}), 400
        
        if ticket.status != 'pagado':
            return jsonify({'message': 'El ticket no se encuentra pago', 'status': 'error'}), 400
        
        customer = ticket.customer

        sale_data = {
            'row': ticket.seat.row,
            'number': ticket.seat.number,
            'section': ticket.seat.section.name,
            'event': ticket.event.name,
            'venue': ticket.event.venue.name,
            'date': ticket.event.date_string,
            'hour': ticket.event.hour_string,
            'price': round(ticket.price/100, 2),
            'discount': round(ticket.discount/100, 2),
            'fee': round(ticket.fee/100, 2),
            'total': round((ticket.price + ticket.fee - ticket.discount)/100, 2),
            'link_reserva': ticket.saleLink,
            'localizador': ticket.saleLocator
        }

        utils.sendqr_for_SuccessfulTicketEmission(current_app.config, db, mail, customer, sale_data, s3, ticket)

        db.session.commit()

        return jsonify({'message': 'Ticket reenviado exitosamente', 'status': 'ok'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al reenviar ticket: {e}")
        return jsonify({'message': 'Error al reenviar ticket', 'status': 'error'}), 500
    finally:
        db.session.close()
    
@backend.route('/load-users', methods=['GET'])
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_users():
    try:
        roles_str = request.args.get('roles', '')
        statuses_str = request.args.get('status', '')

        # Normalize and ignore empty items
        roles = [r for r in roles_str.split(',') if r] if roles_str else []
        statuses = [s for s in statuses_str.split(',') if s] if statuses_str else []

        # Single query for total users and counts by role
        # NOTA: nullif(role != 'admin', True) cuenta admins porque:
        # - Si role != 'admin' es True (no es admin), devuelve NULL
        # - Si role != 'admin' es False (es admin), devuelve False
        # - COUNT solo cuenta valores no-NULL, por lo que cuenta cuando role == 'admin'
        total_users, total_admins, total_tiqueteros, total_customers, total_passive_customers = db.session.query(
            func.count(EventsUsers.CustomerID),
            func.count(func.nullif(EventsUsers.role != 'admin', True)),
            func.count(func.nullif(EventsUsers.role != 'tiquetero', True)),
            func.count(func.nullif(EventsUsers.role != 'customer', True)),
            func.count(func.nullif(EventsUsers.role != 'passive_customer', True)),
        ).one()

        # Construir query de usuarios aplicando filtros solo si vienen en query params
        users_q = EventsUsers.query
        if roles:
            users_q = users_q.filter(EventsUsers.role.in_(roles))
        if statuses:
            users_q = users_q.filter(EventsUsers.status.in_(statuses))

        users = users_q.all()

        users_data = []

        if not users:
            return jsonify({
                'users': users_data,
                'events': [],  # mantengo la forma de respuesta
                'status': 'ok'
            }), 200

        # Recolectar IDs de usuarios con role provider para hacer consultas en batch (evitar N+1)
        provider_ids = [u.CustomerID for u in users if (u.role or '').lower() == 'provider']

        # Mapeo user_id -> [Event, ...]
        assigned_map = {}
        if provider_ids:
            # Eventos asignados vía tabla de asociación EventUserAccess
            rows = (
                db.session.query(Event, EventUserAccess.user_id)
                .join(EventUserAccess, Event.event_id == EventUserAccess.event_id)
                .options(
                    load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string, Event.venue_id),
                    joinedload(Event.venue).load_only(Venue.name)
                )
                .filter(EventUserAccess.user_id.in_(provider_ids))
                .all()
            )
            for ev, uid in rows:
                assigned_map.setdefault(uid, [])
                assigned_map[uid].append(ev)

            # Además, incluir eventos donde Event.event_provider == provider_id (si aplica)
            owned_events = (
                Event.query
                .options(
                    load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string, Event.venue_id),
                    joinedload(Event.venue).load_only(Venue.name)
                )
                .filter(Event.event_provider.in_(provider_ids))
                .all()
            )
            for ev in owned_events:
                uid = ev.event_provider
                if uid is None:
                    continue
                assigned_map.setdefault(uid, [])
                # evitar duplicados por event_id
                if not any(existing.event_id == ev.event_id for existing in assigned_map[uid]):
                    assigned_map[uid].append(ev)

        # Construir users_data y adjuntar eventos asignados si corresponde
        for user in users:
            user_entry = {
                'id': user.CustomerID,
                'firstname': user.FirstName or '',
                'lastname': user.LastName or '',
                'email': user.Email or '',
                'phone': user.PhoneNumber or '',
                'role': user.role,
                'status': user.status,
                'date': user.birthday,
                'gender': user.Gender,
                'joindate': user.Joindate,
                'country_code': user.CountryCode,
            }

            if (user.role or '').lower() == 'provider':
                events_for_user = assigned_map.get(user.CustomerID, [])
                if events_for_user:
                    assigned_events = []
                    for ev in events_for_user:
                        assigned_events.append(
                            getattr(ev, 'event_id', None),
                        )
                    user_entry['assigned_events'] = assigned_events

            users_data.append(user_entry)

        # Construir lista completa de eventos (para select en UI)
        events = Event.query.options(
            load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string),
            joinedload(Event.venue).load_only(Venue.name)
        ).all()

        events_data = []
        for event in events:
            events_data.append({
                'event_id': event.event_id,
                'name': f"{event.name} - {event.venue.name if event.venue else ''} - {event.date_string or ''} {event.hour_string or ''}",
            })

        dashboard_data = {
            'total_users': total_users,
            'total_admins': total_admins,
            'total_tiqueteros': total_tiqueteros,
            'total_customers': total_customers,
            'total_passive_customers': total_passive_customers,
        }

        return jsonify({
            'users': users_data,
            'events': events_data,
            'status': 'ok',
            'dashboard_data': dashboard_data
        }), 200

    except Exception as e:
        db.session.rollback()
        logging.exception(f"Error loading dashboard data: {e}")
        return jsonify({'message': 'Error loading dashboard data', 'status': 'error'}), 500
    finally:
        db.session.close()
    
@backend.route('/create-coupon', methods=['POST'])
@roles_required(allowed_roles=["admin"])
def create_coupon():
    try:
        user_id = get_jwt().get("id")

        # 1. Extraer datos del formulario
        code = request.json.get('code', '').strip()
        description = request.json.get('description', '').strip()
        discount_type = request.json.get('discount_type', '').strip()  # 'percentage' o 'fixed'
        discount_value = request.json.get('discount_value')
        valid_from_str = request.json.get('valid_from', '').strip()
        valid_to_str = request.json.get('valid_to', '').strip()
        max_uses = request.json.get('max_uses')
        applicable_events = request.json.get('applicable_events', [])  # lista de event_ids
        applicable_users = request.json.get('applicable_users', [])  # lista de user_ids

        if not all([code, discount_type, discount_value, valid_from_str, valid_to_str, max_uses]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400

        if discount_type not in ['percentage', 'fixed']:
            return jsonify({'message': 'Tipo de descuento inválido', 'status': 'error'}), 400

        try:
            discount_value = float(discount_value)
            if discount_value <= 0:
                raise ValueError
        except ValueError:
            return jsonify({'message': 'Valor de descuento inválido', 'status': 'error'}), 400

        try:
            valid_from = datetime.strptime(valid_from_str, "%Y-%m-%d").date()
            valid_to = datetime.strptime(valid_to_str, "%Y-%m-%d").date()
            if valid_from > valid_to:
                return jsonify({'message': 'Fecha de inicio debe ser antes de fecha de fin', 'status': 'error'}), 400
        except ValueError:
            return jsonify({'message': 'Formato de fecha inválido', 'status': 'error'}), 400

        try:
            max_uses = int(max_uses)
            if max_uses <= 0:
                raise ValueError
        except ValueError:
            return jsonify({'message': 'Número máximo de usos inválido', 'status': 'error'}), 400
        
        if discount_type == 'percentage' and (discount_value > 100):
            return jsonify({'message': 'El valor de descuento porcentual no puede ser mayor a 100', 'status': 'error'}), 400
        
        if len(applicable_events) > 0:
            if not isinstance(applicable_events, list):
                return jsonify({'message': 'Eventos aplicables debe ser una lista', 'status': 'error'}), 400
            applicable_events = [int(eid) for eid in applicable_events if isinstance(eid, int) or (isinstance(eid, str) and eid.isdigit())]
            # Verificar si todos los event_ids existen en la base de datos
            existing_events = Event.query.filter(Event.event_id.in_(applicable_events)).all()
            existing_event_ids = {event.event_id for event in existing_events}
            invalid_event_ids = [eid for eid in applicable_events if eid not in existing_event_ids]
            if invalid_event_ids:
                return jsonify({'message': f'Los siguientes IDs de eventos no existen: {invalid_event_ids}', 'status': 'error'}), 400
        if len(applicable_users) > 0:
            if not isinstance(applicable_users, list):
                return jsonify({'message': 'Usuarios aplicables debe ser una lista', 'status': 'error'}), 400
            applicable_users = [int(uid) for uid in applicable_users if isinstance(uid, int) or (isinstance(uid, str) and uid.isdigit())]
            # Verificar si todos los user_ids existen en la base de datos
            existing_users = EventsUsers.query.filter(EventsUsers.CustomerID.in_(applicable_users)).all()
            existing_user_ids = {user.CustomerID for user in existing_users}
            invalid_user_ids = [uid for uid in applicable_users if uid not in existing_user_ids]
            if invalid_user_ids:
                return jsonify({'message': f'Los siguientes IDs de usuarios no existen: {invalid_user_ids}', 'status': 'error'}), 400

        # Verificar si el código ya existe
        existing_coupon = Discounts.query.filter(func.lower(Discounts.Code) == code.lower()).first()
        if existing_coupon:
            return jsonify({'message': 'El código de cupón ya existe', 'status': 'error'}), 400

        # Crear el cupón
        new_coupon = Discounts(
            Code=code,
            Description=description,
            Percentage=discount_value if discount_type == 'percentage' else None,
            FixedAmount=discount_value*100 if discount_type == 'fixed' else None,

            DiscountValue=discount_value,
            ValidFrom=valid_from,
            ValidTo=valid_to,
            UsageLimit=max_uses,
            CreatedBy=user_id,
            ApplicableEvents=applicable_events, 
            ApplicableUsers=applicable_users
        ) 
        db.session.add(new_coupon)
        db.session.commit()
        return jsonify({'message': 'Cupón creado exitosamente', 'status': 'ok'}), 201
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear cupón: {e}")
        return jsonify({'message': 'Error al crear cupón', 'status': 'error'}), 500
