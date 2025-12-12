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
import users.utils as users_utils
import uuid

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
        return jsonify(message='La contraseña no es lo suficientemente segura. Debe contener al menos 6 caracteres.'), 400

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
        user = EventsUsers.query.filter(EventsUsers.Email == email, EventsUsers.role != 'unverified_customer').one_or_none() # Buscamos el usuario

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
        
        user = EventsUsers.query.filter(EventsUsers.Email == email, EventsUsers.role != 'unverified_customer').one_or_none() # Buscamos el usuario

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
    
@users.route('/logout', methods=['GET'])
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
    
@users.route('/recovery_password_send_code', methods=['POST'])
#@limiter.limit("5 per minute")
def recovery_password_send_code():
    email = bleach.clean(request.json.get("email", "").strip().lower(), strip=True)
    try:
        # Validación básica de longitud
        if not email or not isinstance(email, str):
            return jsonify({'message': 'Correo electrónico inválido'}), 400
        
        user = EventsUsers.query.filter(EventsUsers.Email == email, EventsUsers.role != 'unverified_customer').one_or_none() # Buscamos el usuario

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
        return jsonify(message='La contraseña no es lo suficientemente segura. Debe contener al menos 6 caracteres.'), 400
    
    try:
        user = EventsUsers.query.filter(EventsUsers.Email == email, EventsUsers.role != 'unverified_customer').one_or_none() # Buscamos el usuario

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
    
@users.route('/update_personal_info', methods=['PUT']) #esta ruta se usa para llenar informacion faltante en el perfil de usuario, principalemnte cuando crea la cuenta con social login
@jwt_required()
def update_personal_info():
    user_id = get_jwt()['id']
    phone = request.json.get("telefono", "").strip()
    cedula = bleach.clean(request.json.get("cedula", ""), strip=True)
    cedula_type = bleach.clean(request.json.get("cedula_type", ""), strip=True)
    codigo_pais = bleach.clean(request.json.get("codigo_pais", ""), strip=True) 
    address = bleach.clean(request.json.get("direccion", ""), strip=True)
    try:
        identification = f"{cedula_type.upper()}{cedula}"
        phone = f"{codigo_pais}{phone}"
        update = users_utils.update_user_info(user_id, codigo_pais, phone, identification, address)

        if update[1] != 200:
            return update

        db.session.commit()
        return jsonify({'status': 'ok', 'message': 'Información actualizada correctamente.'}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al actualizar la información personal: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error al actualizar la información.'}), 500
    
@users.route('/profile', methods=['GET'])
@roles_required(['admin', 'customer', 'tiquetero', 'provider', 'super_admin'])
def get_profile():
    """Obtener información del perfil del usuario autenticado"""
    try:
        # Obtener el ID del usuario del JWT
        claims = get_jwt()
        user_id = claims.get('id')
        
        # Consultar el usuario
        user = EventsUsers.query.filter_by(CustomerID=user_id).one_or_none()
        
        if user is None:
            return jsonify({'status': 'error', 'message': 'Usuario no encontrado'}), 404
        
        # Nombre
        firstname = user.FirstName or ''
        lastname = user.LastName or ''
        
        # Extraer código de país del teléfono (formato E.164: +58...)
        codigo_pais = user.CountryCode or ''
        phone = user.PhoneNumber or ''

        
        # Extraer tipo de cédula (V/E) y número
        cedula_type = ""
        cedula = ""
        if user.Identification:
            # El formato es V12345678 o E12345678
            if len(user.Identification) > 0 and user.Identification[0] in ['V', 'E']:
                cedula_type = user.Identification[0]
                cedula = user.Identification[1:]
            else:
                cedula = user.Identification
        
        # Construir respuesta
        response_data = {
            'status': 'ok',
            'firstname': firstname,
            'lastname': lastname,
            'email': user.Email or '',
            'phone': phone,
            'address': user.Address or '',
            'identification': cedula,
            'cedula_type': cedula_type,
            'codigo_pais': codigo_pais,
            'profile_photo': user.MainPicture or ''
        }

        return jsonify(response_data), 200
        
    except Exception as e:
        logging.error(f"Error obteniendo perfil: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error al obtener el perfil'}), 500

@users.route('/update_personal_info_panel', methods=['PUT'])
@roles_required(['admin', 'customer', 'tiquetero', 'provider', 'super_admin'])
def update_personal_info_panel():
    """Actualizar información personal del usuario"""
    try:
        # Obtener el ID del usuario del JWT
        claims = get_jwt()
        user_id = claims.get('id')
        
        # Obtener datos del request
        firstname = bleach.clean(request.json.get('firstname', ''), strip=True)
        lastname = bleach.clean(request.json.get('lastname', ''), strip=True)
        cedula = bleach.clean(request.json.get('cedula', ''), strip=True)
        cedula_type = bleach.clean(request.json.get('cedula_type', ''), strip=True)
        telefono = bleach.clean(request.json.get('telefono', ''), strip=True)
        direccion = bleach.clean(request.json.get('direccion', ''), strip=True)
        codigo_pais = bleach.clean(request.json.get('codigo_pais', ''), strip=True)
        
        # Validaciones
        
        if not firstname or not lastname:
            return jsonify({'status': 'error', 'message': 'El nombre no puede estar vacío'}), 400
        
        # Validar longitud de nombre y apellido
        if len(firstname) > 50 or len(lastname) > 50:
            return jsonify({'status': 'error', 'message': 'El nombre y apellido no deben exceder los 50 caracteres'}), 400

        # Validar cédula
        if cedula and cedula_type:
            full_cedula = f"{cedula_type.upper()}{cedula}"
            if not utils.cedula_pattern.match(full_cedula):
                return jsonify({'status': 'error', 'message': 'Formato de cédula inválido'}), 400
        
        # Validar y construir teléfono con código de país
        if telefono:
            
            # Validar formato E.164
            if not utils.phone_pattern.match(telefono):
                return jsonify({'status': 'error', 'message': 'Formato de teléfono inválido'}), 400
        
        # Consultar el usuario
        user = EventsUsers.query.filter_by(CustomerID=user_id).one_or_none()
        
        if user is None:
            return jsonify({'status': 'error', 'message': 'Usuario no encontrado'}), 404
        
        # Actualizar campos
        user.FirstName = firstname
        user.LastName = lastname
        
        if cedula and cedula_type:
            user.Identification = f"{cedula_type.upper()}{cedula}"
        
        if telefono:
            user.PhoneNumber = telefono
            user.CountryCode = codigo_pais
        
        if direccion:
            user.Address = direccion
        
        db.session.commit()
        
        return jsonify({
            'status': 'ok',
            'message': 'Información actualizada correctamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error actualizando información personal: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error al actualizar la información'}), 500

@users.route('/change_password', methods=['PUT'])
@roles_required(['admin', 'customer', 'tiquetero', 'provider', 'super_admin'])
def change_password():
    """Cambiar la contraseña del usuario"""
    try:
        # Obtener el ID del usuario del JWT
        claims = get_jwt()
        user_id = claims.get('id')
        
        # Obtener datos del request
        current_password = request.json.get('current_password', '').strip()
        new_password = request.json.get('new_password', '').strip()
        
        # Validaciones
        if not current_password or not new_password:
            return jsonify({'status': 'error', 'message': 'Contraseña actual y nueva son requeridas'}), 400
        
        # Consultar el usuario
        user = EventsUsers.query.filter_by(CustomerID=user_id).one_or_none()
        
        if user is None:
            return jsonify({'status': 'error', 'message': 'Usuario no encontrado'}), 404
        
        # Verificar contraseña actual
        if not check_password_hash(user.Password, current_password):
            return jsonify({'status': 'error', 'message': 'La contraseña actual es incorrecta'}), 401
        
        # Validar fortaleza de la nueva contraseña
        if not signup_utils.strong_password_pattern.match(new_password):
            return jsonify({'status': 'error', 'message': 'La nueva contraseña no es lo suficientemente segura. Debe contener al menos 6 caracteres.'}), 400
        
        # Hashear y actualizar la nueva contraseña
        hashed_password = generate_password_hash(new_password)
        user.Password = hashed_password
        
        db.session.commit()
        
        return jsonify({
            'status': 'ok',
            'message': 'Contraseña actualizada correctamente'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error cambiando contraseña: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error al cambiar la contraseña'}), 500

@users.route('/upload_profile_photo', methods=['POST'])
@roles_required(['admin', 'customer', 'tiquetero', 'provider', 'super_admin'])
def upload_profile_photo():
    """Subir foto de perfil del usuario"""

    S3_BUCKET = current_app.config.get('S3_BUCKET')
    try:
        # Obtener el ID del usuario del JWT
        claims = get_jwt()
        user_id = claims.get('id')
        
        # Verificar que se envió un archivo
        if 'photo' not in request.files:
            return jsonify({'status': 'error', 'message': 'No se envió ningún archivo'}), 400
        
        file = request.files['photo']
        
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No se seleccionó ningún archivo'}), 400
        
        # Validar que sea una imagen
        allowed_mime_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp']
        if file.content_type not in allowed_mime_types:
            return jsonify({'status': 'error', 'message': 'El archivo debe ser una imagen (JPEG, PNG, GIF o WebP)'}), 400
        
        # Validar tamaño (5MB máximo)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)  # Regresar al inicio
        
        max_size = 5 * 1024 * 1024  # 5MB en bytes
        if file_size > max_size:
            return jsonify({'status': 'error', 'message': 'El archivo no debe superar los 5MB'}), 400
        
        # Consultar el usuario
        user = EventsUsers.query.filter_by(CustomerID=user_id).one_or_none()
        
        if user is None:
            return jsonify({'status': 'error', 'message': 'Usuario no encontrado'}), 404
        
        # Eliminar foto anterior de S3 si existe
        if user.MainPicture and user.MainPicture.startswith(f"https://{S3_BUCKET}.s3.amazonaws.com/"):
            try:
                # Extraer la key del URL de S3
                # URL formato: https://bucket.s3.amazonaws.com/path/to/file
                if S3_BUCKET in user.MainPicture:
                    # Extraer la parte después del bucket
                    parts = user.MainPicture.split(f"{S3_BUCKET}.s3.amazonaws.com/")
                    if len(parts) > 1:
                        old_key = parts[1]
                        s3.delete_object(Bucket=S3_BUCKET, Key=old_key)
            except Exception as e:
                logging.warning(f"Error eliminando foto anterior: {e}")
        
        # Generar nombre único para el archivo
        file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"profile_photos/{user_id}/{timestamp}_{uuid.uuid4().hex[:8]}.{file_extension}"
        
        # Subir a S3
        s3.upload_fileobj(
            file,
            S3_BUCKET,
            filename,
            ExtraArgs={'ContentType': file.content_type}
        )
        
        # Construir URL
        photo_url = f"https://{S3_BUCKET}.s3.amazonaws.com/{filename}"
        
        # Actualizar MainPicture en la base de datos
        user.MainPicture = photo_url
        db.session.commit()
        
        return jsonify({
            'status': 'ok',
            'message': 'Foto de perfil actualizada correctamente',
            'photo_url': photo_url
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error subiendo foto de perfil: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error al subir la foto'}), 500

@users.route('/purchase_history', methods=['GET'])
@roles_required(['admin', 'customer', 'tiquetero', 'provider', 'super_admin'])
def get_purchase_history():
    """Obtener el historial de compras del usuario autenticado"""
    try:
        # Obtener el ID del usuario del JWT
        claims = get_jwt()
        user_id = claims.get('id')
        
        # Obtener parámetros de paginación
        page = request.args.get('page', 1, type=int)
        per_page = 5

        # Consultar las ventas del usuario con joins y paginación
        sales_query = Sales.query.options(
            joinedload(Sales.event_rel).joinedload(Event.venue),
            joinedload(Sales.tickets).joinedload(Ticket.seat).joinedload(Seat.section),
            joinedload(Sales.payment),
            joinedload(Sales.purchased_features)
        ).filter(
            Sales.user_id == user_id
        ).order_by(Sales.creation_date.desc())

        total_pages = sales_query.count() // per_page + (1 if sales_query.count() % per_page > 0 else 0)

        sales_pagination = sales_query.paginate(page=page, per_page=per_page, error_out=False)
        sales = sales_pagination.items
        
        # Construir lista de compras
        purchases = []
        
        for sale in sales:
            # Determinar moneda basada en BsDexchangeRate
            currency = "BsD" if sale.BsDexchangeRate else "USD"
            
            # Mapear status
            status_map = {
                'decontado': 'paid',
                'reserva': 'reserved',
                'por cuotas': 'installments',
                'cancelado': 'cancelled'
            }
            status = status_map.get(sale.status, sale.status)
            
            # Obtener método de pago de la tabla Payments si existe
            payment_method = ""
            if sale.payment:
                payment_method = sale.payment.wallet or sale.payment.PaymentMethod or ""
            
            # Construir lista de tickets
            tickets_list = []
            features = []
            for ticket in sale.tickets:
                ticket_data = {
                    'ticket_id': str(ticket.ticket_id),
                    'section': ticket.seat.section.name.replace('20_', ' ') if ticket.seat and ticket.seat.section else '',
                    'row': ticket.seat.row or '' if ticket.seat else '',
                    'number': str(ticket.seat.number) if ticket.seat and ticket.seat.number else '',
                    'price': round(ticket.price/100, 2) if ticket.price is not None else 0.0,
                    'qr_link': ticket.QRlink or ''
                }
                tickets_list.append(ticket_data)

            if sale.purchased_features:
                for feature in sale.purchased_features:
                    feature_data = {
                        'FeatureName': feature.feature.FeatureName,
                        'FeatureCategory': feature.feature.FeatureCategory,
                        'FeatureDescription': feature.feature.FeatureDescription,
                        'PurchaseAmount': round(feature.PurchaseAmount/100, 2) if feature.PurchaseAmount is not None else 0.0,
                        'Quantity': feature.Quantity,
                    }
                    features.append(feature_data)
                
            
            # Construir objeto de compra
            purchase = {
                'sale_id': str(sale.sale_id),
                'event_name': sale.event_rel.name if sale.event_rel else '',
                'event_place': sale.event_rel.venue.name if sale.event_rel and sale.event_rel.venue else '',
                'event_date': sale.event_rel.date_string if sale.event_rel else '',
                'event_hour': sale.event_rel.hour_string if sale.event_rel else '',
                'purchase_date': sale.creation_date.strftime('%Y-%m-%d') if sale.creation_date else '',
                'status': status,
                'total_price': round(sale.paid/100, 2) if sale.paid is not None else 0.0,
                'currency': currency,
                'payment_method': payment_method,
                'tickets': tickets_list,
                'features': features,
                'discount': round(sale.discount/100, 2) if sale.discount is not None else 0.0,
                'fees': round(sale.fee/100, 2) if sale.fee is not None else 0.0,
            }
            
            purchases.append(purchase)
        
        return jsonify({
            'status': 'ok',
            'purchases': purchases,
            'total_pages': total_pages,
        }), 200
        
    except Exception as e:
        logging.error(f"Error obteniendo historial de compras: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error al obtener el historial de compras'}), 500

    