from flask import request, jsonify, Blueprint, make_response, session, current_app, g
from flask_jwt_extended import create_access_token,  set_access_cookies, jwt_required, verify_jwt_in_request
from werkzeug.security import  check_password_hash, generate_password_hash
from extensions import db, s3
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
from extensions import mail
from decorators.utils import optional_roles, roles_required
import signup.utils as signup_utils

users = Blueprint('users', __name__)

@users.route('/register', methods=['POST'])
def register():

    today = datetime.now()  # Define 'today' as the current date and time

    firstname = bleach.clean(request.json.get("signupNombre", ""), strip=True)
    lastname = bleach.clean(request.json.get("signupApellido", ""), strip=True)
    cedula = bleach.clean(request.json.get("signupCedula", ""), strip=True)
    password = request.json.get("signupPassword").strip()
    confirm_password = request.json.get("signupPasswordRepeat").strip()
    phone = request.json.get("signupTelefono").strip()
    email = bleach.clean(request.json.get("signupEmail", "").strip().lower(), strip=True)

    # Validación de datos de entrada
    if not (firstname and lastname and password and confirm_password and phone and email and cedula):
        return jsonify(message='Faltan datos requeridos.'), 400
    
    if not utils.email_pattern.match(email):
        return jsonify(message='Dirección de correo electrónico no válida.'), 400
    
    if not utils.phone_pattern.match(phone):
        return jsonify(message='Número de teléfono no válido. Debe estar en formato E.164.'), 400
    
    if not utils.cedula_pattern.match(cedula.upper()):
        return jsonify(message='Numero de cedula invalido'), 400
    
    if not signup_utils.strong_password_pattern.match(password):
        return jsonify(message='La contraseña no es lo suficientemente segura. Debe contener al menos una letra mayúscula, una minúscula, un número y un carácter especial, y tener una longitud mínima de 8 caracteres.'), 400

    if password != confirm_password:
        return jsonify(message='Las contraseñas no coinciden. Por favor, verifica.'), 400
    
    if len(firstname) > 50 or len(lastname) > 50:
        return jsonify(message='El nombre y apellido no deben exceder los 50 caracteres.'), 400
    if len(email) > 100:
        return jsonify(message='El correo electrónico no debe exceder los 100 caracteres.'), 400
    if len(phone) > 15:
        return jsonify(message='El número de teléfono no debe exceder los 15 caracteres.'), 400
    
    if len(cedula) > 9:
        return jsonify(message='La cédula no debe exceder los 9 caracteres.'), 400
    
    try:
        correo_unverified = db.session.query(EventsUsers).filter(and_(EventsUsers.Email == email, or_(EventsUsers.role == 'passive_customer', EventsUsers.status == 'unverified'))).one_or_none()

        if correo_unverified is not None:
            hashed_password = generate_password_hash(password)

            correo_unverified.Email = email
            correo_unverified.FirstName = firstname
            correo_unverified.LastName = lastname
            correo_unverified.PhoneNumber = phone
            correo_unverified.Identification = cedula.upper()
            correo_unverified.Password = hashed_password
            correo_unverified.Joindate = today
            correo_unverified.strikes = 0
            correo_unverified.status = 'unverified'
            correo_unverified.role='customer'

            log_for_new_user = Logs(
            UserID=correo_unverified.CustomerID,
            Type='nuevo usuario',
            Timestamp=datetime.now(),
            Details=f"Nuevo usuario registrado: {firstname} {lastname} ({email})",
            ) 
            db.session.add(log_for_new_user)

            # Aquí se puede agregar el código para enviar el correo de verificación
            signup_utils.validate_newuser(email, current_app.config, correo_unverified)

            db.session.commit()
            
            response = make_response(jsonify({'status': 'ok'}))
            return response, 201

        correo = db.session.query(EventsUsers).filter(and_(EventsUsers.Email == email, EventsUsers.role != 'passive_customer')).one_or_none()
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
                status='unverified',
                role='customer',
                strikes=0,
                Joindate=today,
                Identification=cedula.upper()
            )
            db.session.add(user)
            db.session.flush()  # Obtener el ID del usuario recién creado

        log_for_new_user = Logs(
            UserID=user.CustomerID,
            Type='nuevo usuario',
            Timestamp=datetime.now(),
            Details=f"Nuevo usuario registrado: {firstname} {lastname} ({email})",
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
    
@users.route('/validate_email_verify_code', methods=['POST'])
#@limiter.limit("5 per minute")
def validate_email_verify_code():
    sender = current_app.config['MAIL_USERNAME'] 
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)

    print("Email recibido para verificación:", email)
    
    try:
        user = EventsUsers.query.filter(EventsUsers.Email == email, EventsUsers.role == 'customer').one_or_none() # Buscamos el usuario

        if user is None:
            return jsonify({'message': 'Usuario no encontrado'}), 404

        if user.status.lower() == "verified":
            return jsonify({'message':'Esta cuenta ya ha sido verificada.'}), 409
        
        if user.status.lower() == 'suspended':
            return jsonify({'message': 'Tu cuenta ha sido suspendida, por favor comunícate con el administrador del sitio'}), 401
        
        # Concatenar el código recibido
        code = ''.join([
            request.json.get(f"input{i}") or ''
            for i in range(1, 7)
        ])

        # Validación básica de longitud
        if len(code) != 6 or not code.isdigit():
            return jsonify({'message':'Código inválido, asegúrate de ingresar correctamente los 6 dígitos.'}), 400
        
        signup_utils.check_validation_attempts(email) # Verificamos el número de intentos de validación

        # Registrar intento
        attempt = VerificationAttempt(email=email, attempt_time=datetime.now())
        db.session.add(attempt)

        # Validar si hay un código válido (no expirado)
        valid_window = datetime.now() - timedelta(minutes=10)
        valid_codes = VerificationCode.query.filter(
            and_(
                VerificationCode.email == email,
                VerificationCode.attempt_time >= valid_window
            )               
        ).all()

        if not valid_codes:
            db.session.commit()
            return jsonify({'message':'El código es incorrecto o ha expirado, intenta nuevamente.'}), 409
        
        for valid_code in valid_codes:
            if check_password_hash(valid_code.code, code): 

                user.Email = email
                user.status = "verified"

                # Renovamos el token del usuario
                access_token = create_access_token(str(user.CustomerID), additional_claims={'role': 'customer', 'username': user.Email, 'status': user.status.lower(), 'id': user.CustomerID})
                session['current_token'] = access_token
                response = make_response(jsonify({'token': access_token, 'status': 'ok', 'redirect': '/', 'role': user.role, 'username': user.Email}), 201) 
                set_access_cookies(response, access_token)

                # Creamos un nuevo token en la tabla Active_tokens
                    
                # OBTENEMOS EL JTI DEL TOKEN RECIÉN CREADO
                access_jti = get_jti(access_token)
                
                # Creamos un nuevo registro en la tabla Active_tokens con el JTI
                newtoken = Active_tokens(CustomerID=user.CustomerID, jti=access_jti)
                db.session.add(newtoken)

                # Eliminamos los códigos válidos
                db.session.delete(valid_code) 
                db.session.commit()

                # Enviamos el correo
                subject = 'Verificación exitosa'
                recipient = email

                message = (
                    f'Hola,\n\n'
                    f'Tu cuenta ha sido verificada exitosamente.\n\n'
                    f'Gracias,\nEquipo de Fiesta Ticket'
                )

                msg = Message(subject, sender=sender, recipients=[recipient])
                msg.body = message

                mail.send(msg)
                return response, 201
            
        # Si el código no está en la lista de códigos válidos:
        db.session.commit()
        logging.warning('El código es incorrecto o ha expirado, intenta nuevamente.')
        return jsonify({'message':'El código es incorrecto o ha expirado, intenta nuevamente.'}), 409
    
    except signup_utils.TooManyAttemptsError as e:
        # Captura la excepción personalizada y retorna la respuesta de error adecuada
        db.session.rollback() # Opcional: si quieres deshacer cualquier cambio pendiente
        return jsonify({'message': e.message}), e.status_code
        
    except Exception as e:
        logging.error(f"Error en la validación del código de verificación: {e}")
        return jsonify({'message': 'Ocurrió un error inesperado.'}), 500

@users.route('/validate_email_resend_code', methods=['POST'])
#@limiter.limit("5 per minute")
def validate_email_resend_code():
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)
    try:
        # Validación básica de longitud
        if not email or not isinstance(email, str):
            return jsonify({'message': 'Correo electrónico inválido'}), 400
        
        user = EventsUsers.query.filter(EventsUsers.Email == email, EventsUsers.role == 'customer').one_or_none() # Buscamos el usuario

        if user is None:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        
        if user.status.lower() == "verified":
            return jsonify({'message':'Esta cuenta ya ha sido verificada.'}), 409
        
        if user.status == 'suspended':
            return jsonify({'message': 'Tu cuenta ha sido suspendida, por favor comunícate con el administrador del sitio'}), 401
        
        # Limitar reenvíos a uno por minuto
        now = datetime.now(timezone.utc)  # Siempre en UTC
        
        if user.LastVerificationAttempt:
            # 1. Convierte t.expires_at a aware ASUMIENDO que es UTC
            if user.LastVerificationAttempt and user.LastVerificationAttempt.tzinfo is None:
                last_verification_aware =user.LastVerificationAttempt.replace(tzinfo=timezone.utc)
            else:
                last_verification_aware = user.LastVerificationAttempt # Ya tiene info de zona horaria
            if (now - last_verification_aware) < timedelta(minutes=1):
                return jsonify({'message': 'Por favor espera un momento antes de solicitar un nuevo código'}), 429
        
        datetime_for_new_resend = (now + timedelta(minutes=1)).isoformat() + "Z"

        signup_utils.check_validation_attempts(email)
        signup_utils.validate_newuser(email, current_app.config, user)
        return jsonify({'message': 'Código enviado', 'status': 'ok', 'datetime_for_new_resend': datetime_for_new_resend})
    
    except signup_utils.TooManyAttemptsError as e:
        db.session.rollback() 
        return jsonify({'message': e.message}), e.status_code

    except Exception as e:
        logging.error(f"Error en la validación del código de verificación: {e}")
        return jsonify({'message': 'Ocurrió un error inesperado'}), 500

@users.route('/login', methods=['POST'])
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
            return jsonify({'status': 'error', 'message': 'Tu cuenta ha sido suspendida por múltiples intentos fallidos. Recupera tu contraseña para continuar.'}), 401

        if check_password_hash(user.Password, password):
            user.strikes = 0
            db.session.commit()

            if user.status == 'unverified':
                return jsonify({'status': 'unverified', 'message': 'Tu cuenta no ha sido verificada. Por favor verifica tu correo electrónico para continuar.'}), 401
            
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
    
@users.route('/recovery_password_send_code', methods=['POST'])
#@limiter.limit("5 per minute")
def recovery_password_send_code():
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)
    try:
        # Validación básica de longitud
        if not email or not isinstance(email, str):
            return jsonify({'message': 'Correo electrónico inválido'}), 400
        
        user = EventsUsers.query.filter(EventsUsers.Email == email, EventsUsers.role == 'customer').one_or_none() # Buscamos el usuario

        if user is None:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        
        if user.status == 'suspended':
            return jsonify({'message': 'Tu cuenta ha sido suspendida, por favor comunícate con el administrador del sitio'}), 401
        
        # Limitar reenvíos a uno por minuto
        now = datetime.now(timezone.utc)  # Siempre en UTC
        
        if user.LastVerificationAttempt:
            # 1. Convierte t.expires_at a aware ASUMIENDO que es UTC
            if user.LastVerificationAttempt and user.LastVerificationAttempt.tzinfo is None:
                last_verification_aware =user.LastVerificationAttempt.replace(tzinfo=timezone.utc)
            else:
                last_verification_aware = user.LastVerificationAttempt # Ya tiene info de zona horaria
            if (now - last_verification_aware) < timedelta(minutes=1):
                return jsonify({'message': 'Por favor espera un momento antes de solicitar un nuevo código'}), 429
        
        datetime_for_new_resend = (now + timedelta(minutes=1)).isoformat() + "Z"

        signup_utils.check_validation_attempts(email)
        signup_utils.recovery_password_code(email, current_app.config, user)
        return jsonify({'message': 'Código enviado', 'status': 'ok', 'datetime_for_new_resend': datetime_for_new_resend})
    
    except signup_utils.TooManyAttemptsError as e:
        db.session.rollback() 
        return jsonify({'message': e.message}), e.status_code

    except Exception as e:
        logging.error(f"Error en la validación del código de verificación: {e}")
        return jsonify({'message': 'Ocurrió un error inesperado'}), 500
    
@users.route('/recovery_password_verify_code', methods=['POST'])
#@limiter.limit("5 per minute")
def recovery_password_verify_code():
    sender = current_app.config['MAIL_USERNAME'] 
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)
    password = request.json.get("newPassword", "").strip()
    confirm_password = request.json.get("confirmPassword", "").strip()

    if not (email and password and confirm_password):
        return jsonify({'message': 'Faltan datos requeridos.'}), 400
    if password != confirm_password:
        return jsonify({'message': 'Las contraseñas no coinciden. Por favor, verifica.'}), 400
    if not signup_utils.strong_password_pattern.match(password):
        return jsonify(message='La contraseña no es lo suficientemente segura. Debe contener al menos una letra mayúscula, una minúscula, un número y un carácter especial, y tener una longitud mínima de 8 caracteres.'), 400
    
    try:
        user = EventsUsers.query.filter(EventsUsers.Email == email, EventsUsers.role == 'customer').one_or_none() # Buscamos el usuario

        if user is None:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        
        if user.status.lower() == 'suspended':
            return jsonify({'message': 'Tu cuenta ha sido suspendida, por favor comunícate con el administrador del sitio'}), 401
        
        # Concatenar el código recibido
        code = ''.join([
            request.json.get(f"input{i}") or ''
            for i in range(1, 7)
        ])

        # Validación básica de longitud
        if len(code) != 6 or not code.isdigit():
            return jsonify({'message':'Código inválido, asegúrate de ingresar correctamente los 6 dígitos.'}), 400
        
        signup_utils.check_validation_attempts(email) # Verificamos el número de intentos de validación

        # Registrar intento
        attempt = VerificationAttempt(email=email, attempt_time=datetime.now())
        db.session.add(attempt)

        # Validar si hay un código válido (no expirado)
        valid_window = datetime.now() - timedelta(minutes=10)
        valid_codes = VerificationCode.query.filter(
            and_(
                VerificationCode.email == email,
                VerificationCode.attempt_time >= valid_window
            )               
        ).all()

        if not valid_codes:
            db.session.commit()
            return jsonify({'message':'El código es incorrecto o ha expirado, intenta nuevamente.'}), 409
        
        for valid_code in valid_codes:
            if check_password_hash(valid_code.code, code): 
                hashed_password = generate_password_hash(password)

                user.Password = hashed_password
                user.status = "verified"
                user.LastVerificationAttempt = None
                user.strikes = 0

                # Renovamos el token del usuario
                access_token = create_access_token(str(user.CustomerID), additional_claims={'role': 'customer', 'username': user.Email, 'status': user.status.lower(), 'id': user.CustomerID})
                session['current_token'] = access_token
                response = make_response(jsonify({'token': access_token, 'status': 'ok', 'redirect': '/', 'role': user.role, 'username': user.Email}), 201) 
                set_access_cookies(response, access_token)

                # Creamos un nuevo token en la tabla Active_tokens
                    
                # OBTENEMOS EL JTI DEL TOKEN RECIÉN CREADO
                access_jti = get_jti(access_token)
                
                # Creamos un nuevo registro en la tabla Active_tokens con el JTI
                newtoken = Active_tokens(CustomerID=user.CustomerID, jti=access_jti)
                db.session.add(newtoken)

                # Eliminamos los códigos válidos
                db.session.delete(valid_code) 
                db.session.commit()

                # Enviamos el correo
                subject = 'Contraseña restablecida exitosamente'
                recipient = email

                message = (
                    f'Hola,\n\n'
                    f'Tu contraseña ha sido reestablecida.\n\n'
                    f'Gracias,\nEquipo de Fiesta Ticket'
                )

                msg = Message(subject, sender=sender, recipients=[recipient])
                msg.body = message

                mail.send(msg)
                return response, 201
            
        # Si el código no está en la lista de códigos válidos:
        db.session.commit()
        logging.warning('El código es incorrecto o ha expirado, intenta nuevamente.')
        return jsonify({'message':'El código es incorrecto o ha expirado, intenta nuevamente.'}), 409
    
    except signup_utils.TooManyAttemptsError as e:
        # Captura la excepción personalizada y retorna la respuesta de error adecuada
        db.session.rollback() # Opcional: si quieres deshacer cualquier cambio pendiente
        return jsonify({'message': e.message}), e.status_code
        
    except Exception as e:
        logging.error(f"Error en la validación del código de verificación: {e}")
        return jsonify({'message': 'Ocurrió un error inesperado.'}), 500