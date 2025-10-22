from flask import request, jsonify, Blueprint, make_response, session, current_app, g
from flask_jwt_extended import create_access_token,  set_access_cookies, jwt_required, verify_jwt_in_request
from werkzeug.security import  check_password_hash, generate_password_hash
from extensions import db, s3
from models import EventsUsers, Revoked_tokens, Event, Venue, Section, Seat, Ticket, Financiamientos, Sales, Logs, Payments, Active_tokens, VerificationCode, VerificationAttempt, Providers
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
from extensions import mail
from decorators.utils import optional_roles, roles_required
import signup.utils as signup_utils
import eventos.utils_whatsapp as WA_utils
import requests
import re
import time
import calendar

backend = Blueprint('backend', __name__)

UPLOAD_FOLDER = "uploads/seats"
ALLOWED_EXTENSIONS = {'csv', 'xls', 'xlsx'}

# Asegura que el folder exista
os.makedirs(UPLOAD_FOLDER, exist_ok=True)



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


eventos = Blueprint('eventos', __name__)

ALLOWED_EXTENSIONS = {'csv', 'xls', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

today = datetime.now()  # Define 'today' as the current date and time

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
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)
    birthday = request.json.get("Birthdate")
    role = request.json.get("role")

    # Validación de datos de entrada
    if not (firstname and lastname and password and confirm_password and phone and email and birthday and gender and role):
        return jsonify(message='Faltan datos requeridos.'), 400
    
    if not utils.email_pattern.match(email):
        return jsonify(message='Dirección de correo electrónico no válida.'), 400
    
    if not utils.phone_pattern.match(phone):
        return jsonify(message='Número de teléfono no válido. Debe estar en formato E.164.'), 400
    
    if not signup_utils.strong_password_pattern.match(password):
        return jsonify(message='La contraseña no es lo suficientemente segura. Debe contener al menos una letra mayúscula, una minúscula, un número y un carácter especial, y tener una longitud mínima de 8 caracteres.'), 400

    if password != confirm_password:
        return jsonify(message='Las contraseñas no coinciden. Por favor, verifica.'), 400
    
    if gender not in ['Male', 'Female']:
        return jsonify(message='Selección de género no válida.'), 400
    
    if role not in ['admin', 'tiquetero']:
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
                Gender=gender
            )
            db.session.add(user)

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
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)
    birthday = request.json.get("Birthdate")
    role = request.json.get("role")

    # Validación de datos de entrada
    if not (firstname and lastname and phone and email and birthday and gender and role):
        return jsonify(message='Faltan datos requeridos.'), 400
    
    if not utils.email_pattern.match(email):
        return jsonify(message='Dirección de correo electrónico no válida.'), 400
    
    if not utils.phone_pattern.match(phone):
        return jsonify(message='Número de teléfono no válido. Debe estar en formato E.164.'), 400
    
    if gender not in ['Male', 'Female']:
        return jsonify(message='Selección de género no válida.'), 400
    
    if role not in ['admin', 'tiquetero']:
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
            if not signup_utils.strong_password_pattern.match(password):
                return jsonify(message='La contraseña no es lo suficientemente segura. Debe contener al menos una letra mayúscula, una minúscula, un número y un carácter especial, y tener una longitud mínima de 8 caracteres.'), 400
            if not confirm_password:
                return jsonify(message='Debes confirmar la contraseña.'), 400
            if password != confirm_password:
                return jsonify(message='Las contraseñas no coinciden. Por favor, verifica.'), 400
            
            hashed_password = generate_password_hash(password)
            user.Password = hashed_password


        user.FirstName = firstname
        user.LastName = lastname
        user.PhoneNumber = phone
        user.birthday = birthday
        user.Gender = gender

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
    
    try:
        user = db.session.query(EventsUsers).filter(EventsUsers.CustomerID == int(customerId)).one_or_none()

        if user is None:
            return jsonify(message='El usuario no existe.'), 409  # 409 Conflicto
        user.status = 'suspended'

        #eliminar el token activo del usuario
        active_tokens = db.session.query(Active_tokens).filter(and_(Active_tokens.CustomerID == user.CustomerID, Active_tokens.ExpiresAt - today > 30)).all()
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

@backend.route('/validate_email_verify_code', methods=['POST'])
#@limiter.limit("5 per minute")
@jwt_required()
def validate_email_verify_code():
    verify_jwt_in_request()
    claims = get_jwt()
    email = claims['username']
    customerId = claims['id']
    sender = current_app.config['MAIL_USERNAME'] 
    
    try:
        user = EventsUsers.query.filter(EventsUsers.CustomerID == customerId).one_or_none() #we search the user

        if user.status.lower() == "verified":
            return jsonify({'message':'This account has already been verified.'}), 409
        
        # Concatenate the received code
        code = ''.join([
            request.json.get(f"input{i}") or ''
            for i in range(1, 7)
        ])

        # Basic length validation
        if len(code) != 6 or not code.isdigit():
            return jsonify({'message':'Invalid code, make sure you enter all 6 digits correctly.'}), 400

        email_exists = EventsUsers.query.filter(and_(EventsUsers.Email == email, not_(EventsUsers.status == 'unverified'))).one_or_none()
        if email_exists:
            return jsonify({'message':'The email address has already been verified or exists.'}), 409
        
        signup_utils.check_validation_attempts(email) #to check the number of validation attempts

        # Register attempt
        attempt = VerificationAttempt(email=email, attempt_time=datetime.now())
        db.session.add(attempt)

        # Validate if there is a valid code (not expired)
        valid_window = datetime.now() - timedelta(minutes=10)
        valid_codes = VerificationCode.query.filter(
            and_(
                VerificationCode.email == email,
                VerificationCode.attempt_time >= valid_window
            )               
        ).all()

        if not valid_codes:
            db.session.commit()
            return jsonify({'message':'The code is incorrect or has expired, try again'}), 409
        
        for valid_code in valid_codes:
            if check_password_hash(valid_code.code, code): 

                user.Email = email
                user.status = "verified"

                #we renew the user token
                access_token = create_access_token(str(user.CustomerID), additional_claims={'role': 'customer', 'username': user.Email, 'status': user.status.lower(), 'id': user.CustomerID})
                session['current_token'] = access_token
                response = make_response(jsonify({'token': access_token, 'status': 'ok', 'redirect': '/'}), 201) 
                set_access_cookies(response, access_token)

                #create a new token in the Active_tokens table
                    
                # OBTENEMOS EL JTI DEL TOKEN RECIÉN CREADO
                access_jti = get_jti(access_token)
                
                # Creamos un nuevo registro en la tabla Active_tokens con el JTI
                newtoken = Active_tokens(CustomerID=user.CustomerID, jti=access_jti)
                db.session.add(newtoken)

                # Delete valid codes
                db.session.delete(valid_code) 
                db.session.commit()

                # Send the email
                subject = 'Successful Verification'
                recipient = email

                message = (
                    f'Hello,\n\n'
                    f'Your account has been successfully verified.\n\n'
                    f'Thanks,\nEquipo de Fiesta Ticket'
                )

                msg = Message(subject, sender=sender, recipients=[recipient])
                msg.body = message

                mail.send(msg)
                return response, 201
            
        #if the code is not in the list of valid codes:
        db.session.commit()
        logging.warning('The code is incorrect or has expired, try again')
        return jsonify({'message':'The code is incorrect or has expired, try again'}), 409
    
    except signup_utils.TooManyAttemptsError as e:
        # Captura la excepción personalizada y retorna la respuesta de error adecuada
        db.session.rollback() # Opcional: si quieres deshacer cualquier cambio pendiente
        return jsonify({'message': e.message}), e.status_code
        
    except Exception as e:
        logging.error(f"Error in verification code validation: {e}")
        return jsonify({'message': 'An unexpected error occurred'}), 500

@backend.route('/validate_email_resend_code', methods=['GET'])
#@limiter.limit("5 per minute")
@jwt_required()
def validate_email_resend_code():
    verify_jwt_in_request()
    claims = get_jwt()
    email = claims['username']
    customerId = claims['id']

    try:
        # Basic length validation
        if not email or not isinstance(email, str):
            return jsonify({'message': 'Invalid email'}), 400
        
        user = EventsUsers.query.filter(EventsUsers.CustomerID == customerId).one_or_none() #we search the user

        if user is None:
            return jsonify({'message': 'User not found'}), 404
        
        now = datetime.now(timezone.utc)  # Siempre en UTC
        
        if user.LastVerificationAttempt and (now - user.LastVerificationAttempt) < timedelta(minutes=1):
            return jsonify({'message': 'Please wait a moment before requesting a new code'}), 429
        
        datetime_for_new_resend = (now + timedelta(minutes=1)).isoformat() + "Z"

        signup_utils.check_validation_attempts(email)
        signup_utils.validate_newuser(email, current_app.config, user)
        return jsonify({'message': 'token sent', 'status': 'ok', 'datetime_for_new_resend': datetime_for_new_resend})
    
    except signup_utils.TooManyAttemptsError as e:
        # Captura la excepción personalizada y retorna la respuesta de error adecuada
        db.session.rollback() 
        return jsonify({'message': e.message}), e.status_code

    except Exception as e:
        logging.error(f"Error in verification code validation: {e}")
        return jsonify({'message': 'An unexpected error occurred'}), 500
    
@backend.route('/validate_email_resend_status', methods=['GET']) #ruta para recopilar timestamp del ultimo send del verification code
#@limiter.limit("5 per minute")
#@roles_required(allowed_roles=["admin", "tiquetero"])
@jwt_required()
def validate_email_resend_status():
    verify_jwt_in_request()
    claims = get_jwt()
    customerId = claims['id']
    customerStatus = claims['status']

    print(claims)

    try:

        if customerStatus:
            if customerStatus.lower() != "unverified":
                return jsonify({'message':'This account has already been verified.', 'redirect': '/'}), 409
        
        user = EventsUsers.query.filter(EventsUsers.CustomerID == customerId).one_or_none() #we search the user

        print(user)

        if user is None:
            return jsonify({'message': 'User not found'}), 404
        
        print(user.LastVerificationAttempt)
        
        if not user.LastVerificationAttempt:
            return jsonify({'message': 'code not found'}), 404
        

        
        now = datetime.now(timezone.utc)  # Siempre en UTC

        if user.LastVerificationAttempt and (now - user.LastVerificationAttempt) > timedelta(minutes=1):
            return jsonify({'message': 'expired'}), 429
        
        datetime_for_new_resend = (now + timedelta(minutes=1)).isoformat() + "Z"

        return jsonify({'status': 'ok', 'datetime_for_new_resend': datetime_for_new_resend})
    
    except signup_utils.TooManyAttemptsError as e:
        # Captura la excepción personalizada y retorna la respuesta de error adecuada
        db.session.rollback() 
        return jsonify({'message': e.message}), e.status_code

    except Exception as e:
        logging.error(f"Error in verification code validation: {e}")
        return jsonify({'message': 'An unexpected error occurred'}), 500
    
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
        # Single query for total users and total admins
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
                'price': round((sale.price + sale.discount - sale.discount )/100, 2),
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
    
@backend.route('/new-event', methods=['POST']) #ruta para crear nuevos eventos
@roles_required(allowed_roles=["admin"])
def new_event():
    try:
        user_id = get_jwt().get("id")

        # 1. Extraer datos del formulario
        event_name = request.form.get('event')
        place = request.form.get('place')
        date = request.form.get('date')
        hour = request.form.get('hour')
        upload_method = request.form.get('uploadMethod')
        seat_file = request.files.get('seatFile')
        event_provider = request.form.get('externalProvider', '')

        if not all([event_name, place, date, hour, event_provider]):
            return jsonify({'message': 'Faltan datos obligatorios', 'status': 'error'}), 400
        
        # 1. Buscar o crear el Venue
        venue = Venue.query.filter_by(name=place).first()
        if not venue:
            venue = Venue(name=place, address="No especificada", city="No especificada")
            db.session.add(venue)
            db.session.flush()  # para obtener venue_id antes de commit
        
        # 2. Crear el Event
        event_date = datetime.strptime(date, "%Y-%m-%d").date()
        event = Event(
            name=event_name,
            date=event_date,
            date_string=date,
            hour_string=hour,
            venue_id=venue.venue_id,
            created_by=user_id,
            Type='Espectaculo',
            event_provider=event_provider
            
        )
        db.session.add(event)
        db.session.flush()  # para obtener event_id

        if upload_method == 'file':

            if not seat_file:
                return jsonify({'message': 'Falta el archivo', 'status': 'error'}), 400

            if not allowed_file(seat_file.filename):
                return jsonify({'message': 'Formato de archivo no permitido', 'status': 'error'}), 400

            # 3. Leer el archivo con pandas (soporta csv y excel)
            if seat_file.filename.endswith('.csv'):
                df = pd.read_csv(seat_file)
            else:
                df = pd.read_excel(seat_file)

            # Normalizamos nombres de columnas
            df.columns = df.columns.str.strip().str.lower()

            # Validar que tenga las columnas correctas
            required_cols = {'asiento', 'seccion', 'precio'}
            if not required_cols.issubset(df.columns):
                return jsonify({'message': 'El archivo no tiene las columnas requeridas', 'status': 'error'}), 400



            # 4. Procesar cada fila del archivo de forma eficiente
            # Cache de secciones y asientos para evitar queries repetidas
            section_cache = {}
            seat_cache = {}
            tickets_to_add = []

            for _, row in df.iterrows():
                asiento = str(row['asiento']).strip()
                seccion = str(row['seccion']).strip()
                precio = int(row['precio'])*100

                # Buscar o crear la sección (cache)
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

                # Dividir el asiento en fila y número
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
                                    # Crear ticket (solo agregamos a la lista, no al session aún)
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
            event_id = request.form.get('externalEvent', '')
            tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
            tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

            if not all([event_id, tickera_id, tickera_api_key]):
                return jsonify({"message": "Faltan parámetros"}), 400
            
            event.event_id_provider = event_id
            
            if event is None or not event.active:
                print("Evento no encontrado o inactivo")
                return jsonify({"message": "Evento no encontrado"}), 404

            url = f'{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/load-tickets'
            params = {
                "query": event.event_id_provider,
                "tickera_id": tickera_id,
                "tickera_api_key": tickera_api_key
            }

            # Hacer el request
            response = requests.get(url, params=params, timeout=100)

            # Retornar el resultado directamente al cliente
            if response.status_code == 200:
                tickets = response.json().get("tickets", [])

                print(tickets)

                #aca se crean los tickets como se hace con el archivo
                section_cache = {}
                seat_cache = {}
                tickets_to_add = [] # Lista para almacenar los tickets a insertar
                for ticket_data in tickets:
                    asiento = str(ticket_data.get('seat', '')).strip()
                    seccion = str(ticket_data.get('section', '')).strip()
                    precio = int(ticket_data.get('price', 0))
                    ticket_id_fromprovider = int(ticket_data.get('ticket_id_provider', 0))

                    if not all([asiento, seccion, precio, ticket_id_fromprovider]):
                        return jsonify({'message': 'Datos incompletos en el ticket desde la API', 'status': 'error'}), 400

                    # Buscar o crear la sección (cache)
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

                    # Dividir el asiento en fila y número
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

                    # Crear ticket (solo agregamos a la lista, no al session aún)
                    ticket = Ticket(
                        event_id=event.event_id,
                        ticket_id_provider=ticket_id_fromprovider,
                        seat_id=seat.seat_id,
                        price=precio,
                        status='disponible',
                        created_by=user_id
                    )
                    tickets_to_add.append(ticket)
                    

            else:
                return jsonify({
                    "status": "error",
                    "code": response.status_code,
                    "message": response.json().get("message", "Error desconocido")
                }), response.status_code



        # Bulk insert de tickets
        db.session.add_all(tickets_to_add)
        db.session.commit()

        return jsonify({'message': 'Evento y tickets creados exitosamente', 'status': 'ok'}), 200
    
    except requests.exceptions.RequestException as e:
        db.session.rollback()
        return jsonify({"message": f"Error en el request: {str(e)}"}), 500

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear evento: {e}")
        return jsonify({'message': 'Error al crear evento', 'status': 'error'}), 500
    
@backend.route('/load-events', methods=['GET']) #ver eventos creados
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_events():
    try:
        events = Event.query.all()
        providers = Providers.query.all()

        events_list = []
        for event in events:
            # Buscamos todos los eventos con el mismo nombre para agrupar sus venues
            same_events = Event.query.filter_by(name=event.name).all()

            venues_list = []
            for ev in same_events:
                venues_list.append({
                    "venue_id": ev.venue.venue_id,
                    "name": ev.venue.name,
                    "address": ev.venue.address,
                    "city": ev.venue.city
                })

            events_list.append({
                "event_id": event.event_id,
                "name": event.name,
                "description": event.description,
                "date": event.date.isoformat(),
                "date_string": event.date_string,
                "hour_string": event.hour_string,
                "venue": {
                    "venue_id": event.venue.venue_id,
                    "name": event.venue.name,
                    "address": event.venue.address,
                    "city": event.venue.city
                },
                "venues": venues_list
            })

        providers_list = []
        for provider in providers:
            providers_list.append({
                "ProviderID": provider.ProviderID,
                "ProviderName": provider.ProviderName,
            })


        all_events = {event["event_id"]: event for event in events_list}.values() # Eliminar duplicados por event_id
        unique_events = {event["name"]: event for event in events_list}.values() # Eliminar duplicados por nombre de evento

        return jsonify({"events": list(all_events), "unique_events": list(unique_events), 'status': 'ok', "providers": providers_list}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear evento: {e}")
        return jsonify({'message': 'Error al crear evento', 'status': 'error'}), 500
    
@backend.route('/load-tickets', methods=['GET']) #ver paquetes o ventas en general
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_tickets():
    try:

        from_date_str = request.args.get('from_date', '')
        statuses_str = request.args.get('status', '')

        if not from_date_str and not statuses_str:
            return jsonify({'message': 'Se requiere al menos un filtro (from_date o status)', 'status': 'error'}), 400
    
        # Usamos joinedload para evitar N+1 queries
        events = Event.query.options(
            joinedload(Event.venue).load_only(
                Venue.venue_id, Venue.name, Venue.address, Venue.city
            ),
            load_only(Event.event_id, Event.name, Event.description, Event.date, Event.date_string, Event.hour_string, Event.venue_id)
        ).filter(Event.active == True).all()

        events_dict = {}
        for event in events:
            if event.name not in events_dict:
                events_dict[event.name] = {
                    "event_id": event.event_id,
                    "name": event.name,
                    "description": event.description,
                    "venues": []
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

        
        if from_date_str:
            from_date_str = from_date_str.split('T')[0]  # Extraer solo la parte de la fecha
            try:
                from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
            except ValueError:
                return jsonify({'message': 'Formato de fecha inválido. Usa YYYY-MM-DD.', 'status': 'error'}), 400

        statuses = statuses_str.split(',') if statuses_str else []

        # Información de ventas
        query = Sales.query.options(
            joinedload(Sales.customer).load_only(EventsUsers.FirstName, EventsUsers.LastName, EventsUsers.Email),
            joinedload(Sales.event_rel).load_only(Event.name),
            load_only(Sales.sale_id, Sales.status, Sales.price, Sales.discount, Sales.fee, Sales.saleLocator, Sales.saleLink, Sales.creation_date)
        )

        filters = []
        if from_date:
            from_date = from_date.date()  # asegúrate de tener un date
            filters.append(Sales.creation_date >= from_date)
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

        return jsonify({"unique_events": list(events_dict.values()), "events": list(events_dict.values()), "sales": sales_data, "status": "ok"}), 200


    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al crear evento: {e}")
        return jsonify({'message': 'Error al crear evento', 'status': 'error'}), 500
    
@backend.route('/load-available-tickets', methods=['GET'])
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_available_tickets():
    try:
        event_name = request.args.get('event', '')
        venue = request.args.get('venue', '')
        date_and_time = request.args.get('date', '')
        date, time = ('', '')

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
                Event.Type
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

        # ✅ Traer los tickets disponibles de una sola vez, con relaciones precargadas
        tickets = (
            Ticket.query.options(
                joinedload(Ticket.seat)
                .joinedload(Seat.section),  # Carga Section en el mismo query
                load_only(Ticket.ticket_id, Ticket.price, Ticket.status, Ticket.seat_id)
            )
            .filter(
                and_(
                    Ticket.event_id == event.event_id,
                    or_(
                        Ticket.status == 'disponible',
                        Ticket.status == 'en carrito'
                    )
                )
            )
            .all()
        )

        # ✅ Procesar los tickets agrupados por sección y fila
        sections_dict = {}
        now = datetime.now(timezone.utc)  # Siempre en UTC
        
        for t in tickets:
            if t.status == 'en carrito':
                if t.expires_at and t.expires_at.tzinfo is None:
                    expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
                else:
                    expires_at_aware = t.expires_at # Ya tiene info de zona horaria
                if not expires_at_aware or expires_at_aware > now:
                    # Si el ticket está "en carrito" pero ha expirado, lo marcamos como disponible
                    continue  # No lo incluimos en la lista de tickets disponibles

            seat = t.seat
            section = seat.section if seat else None

            section_name = section.name if section else "Sin sección"
            row_name = seat.row if seat else "Sin fila"

            if section_name not in sections_dict:
                sections_dict[section_name] = {"section": section_name, "rows": {}}
            if row_name not in sections_dict[section_name]["rows"]:
                sections_dict[section_name]["rows"][row_name] = []

            sections_dict[section_name]["rows"][row_name].append({
                "ticket_id": t.ticket_id,
                "price": t.price,
                "status": t.status,
                "number": seat.number if seat else None
            })

        # ✅ Convertir a lista
        tickets_list = [
            {
                "section": section_name,
                "rows": [
                    {"row": row_name, "seats": seats}
                    for row_name, seats in section_data["rows"].items()
                ],
            }
            for section_name, section_data in sections_dict.items()
        ]

        return jsonify({
            "tickets": tickets_list,
            "fee": event.Fee,
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
        event_id = request.args.get('query', '')
        if not event_id.isdigit():
            return jsonify({"message": "ID de evento inválido"}), 400

        event = Event.query.filter_by(event_id=int(event_id)).one_or_none()
        if not event:
            return jsonify({"message": "No se encontró el evento"}), 404

        tickets_list = []
        tickets_stats = {}

        if event.Type == 'Espectaculo': #si se trata de un evento, se cargan los tickets
            # Traer todos los tickets excepto los disponibles, optimizando con joinedload y load_only

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
                    Ticket.status == 'pagado'
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
                    tickets_counts.get(s, 0) for s in ["reservado", "pagado por verificar", "por cuotas", "en carrito", "pendiente pago"]
                ),
                "paid_tickets": tickets_counts.get("pagado", 0),
            }

            SVGmap = event.SVGmap if event.SVGmap else ""

            for t in tickets:
                tickets_list.append({
                    "sale_id": t.sale_id,
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
                    "ticket_id": t.ticket_id,
                })

        else:  # otro tipo de evento → ventas, se cargan las ventas
            sales = Sales.query.filter(Sales.event == event.event_id).all()

            for s in sales:
                tickets_list.append({
                    "sale_id": s.sale_id,
                    "fullname": f"{s.customer.FirstName} {s.customer.LastName}" if s.customer else "",
                    "status": s.StatusFinanciamiento,
                    "event": s.event_rel.name if s.event_rel else "",
                    "price": round(s.price / 100, 2),
                    "saleLocator": s.saleLocator,
                    "saleLink": s.saleLink,
                    "email": s.customer.Email if s.customer else "",
                })

        return jsonify({
            "status": "ok",
            "type": event.Type,
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
        # 3️⃣ Hacer request externo
        # ---------------------------------------------------------------
        url = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/load-map"
        params = {
            "query": event.event_id_provider,
            "tickera_id": tickera_id,
            "tickera_api_key": tickera_api_key
        }

        req_start = time.perf_counter()
        response = requests.get(url, params=params, timeout=60)
        req_end = time.perf_counter()

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
    firstname = request.json.get('firstname', '')
    lastname = request.json.get('lastname', '')
    date = request.json.get('PaymentDate')

    tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
    tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

    # ----------------------------------------------------------------
    # 1️⃣ Validaciones iniciales
    # ----------------------------------------------------------------
    if not all([user_id, payment_method, tickera_id, tickera_api_key, selectedSeats, payment_reference, email, firstname, lastname, date, contact_phone, contact_phone_prefix]):
        return jsonify({"message": "Faltan parámetros obligatorios"}), 400

    if payment_method not in ["pagomovil", "efectivo", "zelle", "binance", "square", "tarjeta de credito"]:
        return jsonify({"message": "Método de pago no válido"}), 400
    
    if len(selectedSeats) == 0:
        return jsonify({"message": "No se seleccionaron asientos"}), 400
    
    email = email.strip().lower()
    if not utils.email_pattern.match(email):
        return jsonify({"message": "Correo electrónico no válido"}), 400

    # ----------------------------------------------------------------
    # 2️⃣ Validar información del pago
    # ----------------------------------------------------------------
    full_phone_number = None

    if not all([contact_phone, contact_phone_prefix]):
        print(contact_phone, contact_phone_prefix)
        return jsonify({"message": "Complete todos los campos requeridos"}), 400

    full_phone_number = f"{contact_phone_prefix}{contact_phone}".replace("+", "").replace(" ", "").replace("-", "")
    if not utils.phone_pattern.match(full_phone_number):
        return jsonify({"message": "Número de teléfono no válido"}), 400

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
            status='unverifed',
            CreatedBy=user_id,
        )
        db.session.add(customer)
        db.session.flush()  # para obtener customer_id

    # ----------------------------------------------------------------
    # 4️⃣ Obtener tickets en carrito
    # ----------------------------------------------------------------
    ticket_ids = [int(s['ticket_id']) for s in selectedSeats if 'ticket_id' in s]

    tickets_en_carrito = Ticket.query.filter(
        and_(
            Ticket.ticket_id.in_(ticket_ids),
        )
    ).all()  # Bloquear

    if not tickets_en_carrito or len(tickets_en_carrito) != len(ticket_ids):
        return jsonify({"message": "Algunos tickets no están disponibles"}), 400

    event = tickets_en_carrito[0].event

    if not event or not event.active:
        return jsonify({"message": "Evento no encontrado o inactivo"}), 404

    now = datetime.now(timezone.utc)  # Siempre en UTC

    # ----------------------------------------------------------------
    # 5️⃣ Bloquear en Tickera (antes de modificar BD local)
    # ----------------------------------------------------------------
    url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/block-tickets"
    payload = {
        "event": event.event_id_provider,
        "tickets": [
            {"ticket_id_provider": t.ticket_id_provider, "price": t.price}
            for t in tickets_en_carrito
        ],
        "tickera_id": tickera_id,
        "tickera_api_key": tickera_api_key,
        "type_of_sale": "admin_sale"
    }
    try:
        response_block = requests.post(url_block, json=payload, timeout=30)
        # 1️⃣ Validar respuesta del bloqueo
        if response_block.status_code != 200:
            db.session.rollback()
            return jsonify({
                "status": "error",
                "code": response_block.status_code,
                "message": response_block.json().get("message", "Error desconocido en Tickera")
            }), response_block.status_code
    except requests.exceptions.RequestException as e:
        db.session.rollback()
        logging.error(f"Error al bloquear tickets en Tickera: {str(e)}")
        return jsonify({"message": "Error al conectar con Tickera para bloquear tickets"}), 502

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
            user_id=customer.CustomerID,
            status=payment_status,
            created_by=user_id,
            StatusFinanciamiento='decontado',
            event=event.event_id,
            fee=total_fee,
            discount=0,
            ContactPhoneNumber=full_phone_number,
            creation_date=date
        )
        db.session.add(sale)
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
            Amount=total_price + total_fee,
            PaymentDate=today,
            PaymentMethod=payment_method,
            Reference=payment_reference,
            Status='pendiente',
            CreatedBy=user_id,
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

        sale_data = {
            'sale_id': sale.sale_id,
            'event': sale.event_rel.name,
            'venue': sale.event_rel.venue.name,
            'date': sale.event_rel.date_string,
            'hour': sale.event_rel.hour_string,
            'price': round(sale.price / 10000, 2),
            'discount': round(sale.discount / 100, 2),
            'fee': round(sale.fee / 10000, 2),
            'total_abono': round((total_price + sale.fee) / 100, 2),
            'due': round(0, 2),
            'payment_method': payment_method.capitalize(),
            'payment_date': today.strftime('%d-%m-%Y'),
            'reference': payment_reference or 'N/A',
            'link_reserva': qr_link,
            'localizador': localizador,
            'status': 'pagado',
            'title': 'Estamos procesando tu abono',
            'subtitle': 'Te notificaremos una vez que haya sido aprobado',
        }     

        # Confirmar todo
        db.session.commit()

        # ---------------------------------------------------------------
        # Enviar notificación por email al cliente
        # ---------------------------------------------------------------

        #utils.sendnotification_for_PaymentStatus(current_app.config, db, mail, customer, selectedSeats, sale_data)

        # ---------------------------------------------------------------
        # Notificar a administración sobre nueva venta/pago por whatsapp
        # ---------------------------------------------------------------
        WA_utils.send_new_sale_notification(current_app.config, customer, selectedSeats, sale_data, full_phone_number)
        # ---------------------------------------------------------------

        return jsonify({"message": "Tickets bloqueados y venta registrada exitosamente", "status": "ok"}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error registrando venta o pago: {str(e)}")
        return jsonify({"message": "Error al registrar la venta o pago", "status": "error"}), 500
    finally:
        db.session.close()
    
@backend.route('/canjear-ticket', methods=['GET'])  #canjeo de tickets
@roles_required(allowed_roles=["admin", "tiquetero"])
def canjear_ticket():
    ticket_id = request.args.get('query', '')
    try:
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
            ticket.canjeo_date = today
            db.session.commit()

            return jsonify({'message': 'Ticket canjeado exitosamente', 'status': 'ok', 'ticket_status': 'used'}), 200

        else:
            return jsonify({'message': 'Ticket no encontrado', 'status': 'ok', 'ticket_status': 'missing'}), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar ticket: {e}")
        return jsonify({'message': 'Error al buscar ticket', 'status': 'error'}), 500

@backend.route('/customize-reservation', methods=['GET']) #endpoint para recopilar informacion de la reserva (admin)
@roles_required(allowed_roles=["admin", "tiquetero"])
def customize_reservation():

    sale_id = request.args.get('query', '')

    try:
        if sale_id:
            sale = Sales.query.filter(
                and_(
                    Sales.sale_id== int(sale_id),
                )
            ).one_or_none()

            if not sale:
                return jsonify({'message': 'Reserva no encontrada', 'status': 'ok', 'reservation_status': 'missing'}), 400

            if sale.status == 'cancelado':
                return jsonify({'message': 'Reserva cancelada, por favor contacta a un administrador', 'status': 'ok', 'reservation_status': 'broken'}), 400
            
            payments_list = []
            payments = Payments.query.filter(Payments.SaleID == sale.sale_id).all()
            if payments:
                for entry in payments:

                    # Format the date as dd/mm/yyyy if possible
                    try:
                        formatted_date = entry.PaymentDate.strftime('%d/%m/%Y')
                    except Exception:
                        formatted_date = str(entry.PaymentDate)
                    payments_list.append({
                        'amount': round(int(entry.Amount)/100, 2),
                        'date': formatted_date,
                        'paymentMethod': entry.PaymentMethod,
                        'paymentReference': entry.Reference,
                        'paymentVerified': entry.Status
                    })

            information = {}

            event_name = sale.event_rel.name if sale.event else ''
            venue_name = sale.event_rel.venue.name if sale.event and sale.event_rel.venue else ''
            event_date = sale.event_rel.date_string if sale.event else ''
            event_hour = sale.event_rel.hour_string if sale.event else ''
            
            if sale.financiamiento_rel and sale.financiamiento_rel.Type == 'reserva':

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

                fee = sale.fee if sale.fee else 0
                discount = sale.discount if sale.discount else 0

                information['due_date'] = [sale.financiamiento_rel.Deadline]
                information['payments'] = payments_list
                information['type'] = sale.financiamiento_rel.Type
                information['items'] = tickets
                information['subtotal'] = round((sale.price)/100, 2)
                information['total_price'] = round((sale.price + fee - discount)/100, 2)
                information['paid'] = round(sale.paid/100, 2)
                information['due'] = round((sale.price + fee - discount - sale.paid)/100, 2)
                information['fee'] = round(fee)/100
                information['discount'] = round(discount)/100
                information['status'] = sale.status
                information['event'] = event_name
                information['venue'] = venue_name
                information['date'] = event_date
                information['hour'] = event_hour
                information['locator'] = sale.saleLocator
                information['StatusFinanciamiento'] = sale.StatusFinanciamiento 
                information['Fullname'] = [(sale.customer.FirstName + ' ' + sale.customer.LastName) if sale.customer else '']
                information['Email'] = [sale.customer.Email if sale.customer else '']
                information['saleId'] = sale.sale_id

            elif sale.financiamiento_rel and sale.financiamiento_rel.Type == 'por cuotas':
                logging.info('es financiado por cuotas')
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

                fee = sale.fee if sale.fee else 0
                discount = sale.discount if sale.discount else 0

                information['due_dates'] = [due_dates]
                information['payments'] = payments_list
                information['type'] = sale.financiamiento_rel.Type
                information['items'] = tickets
                information['subtotal'] = round((sale.price)/100, 2)
                information['total_price'] = round((sale.price + fee - discount)/100, 2)
                information['paid'] = round(sale.paid/100, 2)
                information['due'] = round((sale.price + fee - discount - sale.paid)/100, 2)
                information['fee'] = round(fee)/100
                information['discount'] = round(discount)/100
                information['status'] = sale.status
                information['event'] = event_name
                information['venue'] = venue_name
                information['date'] = event_date
                information['hour'] = event_hour
                information['locator'] = sale.saleLocator
                information['StatusFinanciamiento'] = sale.StatusFinanciamiento 
                information['Fullname'] = [(sale.customer.FirstName + ' ' + sale.customer.LastName) if sale.customer else '']
                information['Email'] = [sale.customer.Email if sale.customer else '']
                information['sale_id'] = sale.sale_id

            else:
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

                fee = sale.fee if sale.fee else 0
                discount = sale.discount if sale.discount else 0

                information['due_dates'] = [due_dates]
                information['payments'] = payments_list
                information['type'] = "decontado"
                information['items'] = tickets
                information['subtotal'] = round((sale.price)/100, 2)
                information['total_price'] = round((sale.price + fee - discount)/100, 2)
                information['paid'] = round(sale.paid/100, 2)
                information['due'] = round((sale.price + fee - discount - sale.paid)/100, 2)
                information['fee'] = round(fee)/100
                information['discount'] = round(discount)/100
                information['status'] = sale.status
                information['event'] = event_name
                information['venue'] = venue_name
                information['date'] = event_date
                information['hour'] = event_hour
                information['locator'] = sale.saleLocator
                information['StatusFinanciamiento'] = sale.StatusFinanciamiento 
                information['Fullname'] = [(sale.customer.FirstName + ' ' + sale.customer.LastName) if sale.customer else '']
                information['Email'] = [sale.customer.Email if sale.customer else '']
                information['sale_id'] = sale.sale_id

            return jsonify({'message': 'Reserva existente', 'status': 'ok', 'information': information}), 200

        else:
            return jsonify({'message': 'Reserva no encontrada', 'status': 'error'}), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al buscar reserva: {e}")
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

        if (sale.paid + fee + received - discount) > sale.price:
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
        if new_payment_entry.sale.event_rel.Type == 'Espectaculo':

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

        if not all([payment_id, received, PaymentMethod, aprobacion]):
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

        if (payment.sale.paid + received) > (payment.sale.price + payment.sale.fee - payment.sale.discount):
            return jsonify({'message': 'El monto abonado excede el total de la venta. El abono no puede ser procesado.', 'status': 'error'}), 400

        # 3️⃣ Datos auxiliares
        customer = payment.sale.customer
        paymentDeadline = payment.sale.financiamiento_rel.Deadline if (payment.sale.financiamiento_rel and payment.sale.financiamiento_rel.Deadline) else ''

        # 4️⃣ Verificar tipo de evento
        if payment.sale.event_rel.Type == 'Espectaculo':

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
                    'section': ticket.seat.section.name,
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

                        # 🔗 Llamar a Tickera para liberar los tickets bloqueados
                        try:
                            tickera_id = current_app.config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
                            tickera_api_key = current_app.config.get('FIESTATRAVEL_TICKERA_API_KEY', '')
                            url_block = f"{current_app.config['FIESTATRAVEL_API_URL']}/eventos_api/release-tickets"
                            event = payment.sale.event_rel

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
                if payment.sale.paid + payment.sale.discount >= payment.sale.price + payment.sale.fee:

                    # ---------------------------------------------------------------
                    # 7️⃣ Llamar a la API para calcular la tasa en bolivares BCV
                    # ---------------------------------------------------------------
                    url_exchange_rate_BsD = f"https://api.dolarvzla.com/public/exchange-rate"

                    response_exchange = requests.get(url_exchange_rate_BsD, timeout=20)
                    exchangeRate = 0

                    if response_exchange.status_code != 200:
                        logging.error(response_exchange.status_code)
                        return jsonify({"message": "No se pudo obtener la tasa de cambio. Por favor, inténtelo de nuevo más tarde."}), 500
                    exchange_data = response_exchange.json()
                    exchangeRate = exchange_data.get("current", {}).get("usd", 0)

                    if exchangeRate <= 200.00: #minimo aceptable al 18 octubre 2025
                        return jsonify({"message": "Tasa de cambio inválida. Por favor, inténtelo de nuevo más tarde."}), 500
                    
                    exchangeRate = int(exchangeRate*100)


                    payment.sale.StatusFinanciamiento = 'pagado' #completamente pagado
                    payment.sale.status = 'pagado' #cambiamos el estado de la venta a aprobado si ya se pagó todo
                    ticket_ids = payment.sale.ticket_ids.split('|') if '|' in payment.sale.ticket_ids else [payment.sale.ticket_ids]

                    for ticket_id in ticket_ids:
                        if not ticket_id:
                            continue

                        ticket = Ticket.query.get(int(ticket_id))
                        if not ticket:
                            return jsonify({'message': 'No se encontró el ticket asociado', 'status': 'error'}), 400

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
                            'discount': round(ticket.discount / 100, 2),
                            'fee': round(ticket.fee / 100, 2),
                            'total': round((ticket.price + ticket.fee - ticket.discount) / 100, 2),
                            'link_reserva': qr_link,
                            'localizador': localizador
                        }

                        utils.sendqr_for_SuccessfulTicketEmission(current_app.config, db, mail, customer, sale_data, s3, ticket)

                    IVA = current_app.config.get('IVA_PERCENTAGE', 0) / 100
                    amount_with_IVA = int(received * IVA / (1 + IVA))
                    IVA_amount = received - amount_with_IVA

                    sale_data = {
                        'sale_id': str(payment.sale.sale_id),
                        'event': payment.sale.event_rel.name,
                        'venue': payment.sale.event_rel.venue.name,
                        'date': payment.sale.event_rel.date_string,
                        'hour': payment.sale.event_rel.hour_string,
                        'price': round(payment.sale.price*exchangeRate / 10000, 2),
                        'iva_amount': round(IVA_amount*exchangeRate / 10000, 2),
                        'net_amount': round(amount_with_IVA*exchangeRate / 10000, 2),
                        'total_abono': round(received*exchangeRate / 10000, 2),
                        'payment_method': PaymentMethod,
                        'payment_date': PaymentDate,
                        'reference': PaymentReference,
                        'link_reserva': reserva_link,
                        'localizador': payment.sale.saleLocator,
                        'exchange_rate_bsd': round(exchangeRate/100, 2),
                        'status': 'aprobado',
                        'title': 'Tu pago ha sido procesado exitosamente',
                        'subtitle': 'Gracias por tu compra, a continuación encontrarás los detalles de tu factura'
                    }
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

        if sale.event_rel and sale.event_rel.Type == 'Espectaculo':
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
    
@backend.route('/modify-reservation', methods=['POST']) #para modificarr una reserva (nombre o email)
@roles_required(allowed_roles=["admin", "tiquetero"])
def modify_reservation():
    try:
        user_id = get_jwt().get("id")
        user_role = get_jwt().get("role")

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
            eventType = sale.event_rel.Type

            # Actualizar el estado de los tickets asociados si estos ya fueron emitidos
            if eventType == 'Espectaculo':

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
    
@backend.route('/load-users', methods=['GET'])
@roles_required(allowed_roles=["admin", "tiquetero"])
def load_users():
    try:

        roles_str = request.args.get('roles', '')
        statuses_str = request.args.get('status', '')

        roles = roles_str.split(',') if roles_str else []
        statuses = statuses_str.split(',') if statuses_str else []

        # Single query for total users and total admins
        total_users, total_admins, total_tiqueteros, total_customers, total_passive_customers = db.session.query(
            func.count(EventsUsers.CustomerID),
            func.count(func.nullif(EventsUsers.role != 'admin', True)),
            func.count(func.nullif(EventsUsers.role != 'tiquetero', True)),
            func.count(func.nullif(EventsUsers.role != 'customer', True)),
            func.count(func.nullif(EventsUsers.role != 'passive_customer', True)),
        ).one()

        # Obtener todos los usuarios
        users = EventsUsers.query.filter(
            and_(EventsUsers.role.in_(roles),
                 EventsUsers.status.in_(statuses),
            )
        ).all()

        users_data = []

        if not users:
            return jsonify({
                'users': users_data,
                'status': 'ok'
            }), 200

        # Crear una lista de diccionarios con los datos de los usuarios
        
        for user in users:
            users_data.append({
                'id': user.CustomerID,
                'firstname': user.FirstName if user.FirstName else '',
                'lastname': user.LastName if user.LastName else '',
                'email': user.Email,
                'phone': user.PhoneNumber,
                'role': user.role,
                'status': user.status,
                'date': user.birthday,
                'gender': user.Gender,
                'joindate': user.Joindate,
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
            'status': 'ok',
            'dashboard_data': dashboard_data
        }), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error loading dashboard data: {e}")
        return jsonify({'message': 'Error loading dashboard data', 'status': 'error'}), 500