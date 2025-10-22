from flask import jsonify
from extensions import db, mail
from flask_mail import Message
from datetime import datetime, timedelta
import secrets
from werkzeug.security import generate_password_hash
from sqlalchemy import and_
import logging
import re
from models import VerificationAttempt, VerificationCode, EventsUsers
from datetime import datetime, timezone

def validate_newuser(email, config, user):
    sender = config.get('MAIL_USERNAME')
    try:
        if not email:
            return jsonify(message='El correo electrónico es obligatorio.'), 400

        email = email.lower().strip()
        code = generate_secure_code()
        now = datetime.now(timezone.utc)  # Siempre en UTC
        hashed = hash_code(code)

        # Verifica si el usuario ya existe y no está marcado como UNVERIFIED
        existing_user = EventsUsers.query.filter(
            and_(EventsUsers.Email == email, EventsUsers.status == 'verified')
        ).one_or_none()

        if existing_user:
            return jsonify(message='Este correo electrónico ya está verificado, intenta con uno diferente.'), 409

        # Elimina códigos previos de verificación para este correo, si existen (previene duplicados)
        VerificationCode.query.filter_by(email=email).delete()

        # Guarda nuevo código hashed
        new_code = VerificationCode(email=email, code=hashed)
        db.session.add(new_code)
        

        # Construcción del correo
        subject = 'Verificación de usuario - Fiesta Ticket'
        message = (
            f"Hola,\n\n"
            "Gracias por unirte a Fiesta Ticket. Si no realizaste esta solicitud, puedes ignorar este mensaje.\n\n"
            f"Aquí tienes tu código para verificar tu cuenta (válido por 10 minutos):\n\n{code}\n\n"
            "Gracias,\nEquipo de Fiesta Ticket"
        )

        msg = Message(subject, sender=sender, recipients=[email])
        msg.body = message

        # Envía el correo
        mail.send(msg)

        user.LastVerificationAttempt = now

        print(user.LastVerificationAttempt)

        db.session.commit()

        return jsonify(message='Se ha enviado un código de verificación a tu correo electrónico.'), 200

    except Exception as e:
        logging.exception("Error al enviar el correo de verificación")
        db.session.rollback()
        return jsonify(message='Ocurrió un error al enviar el correo de verificación.'), 500
    
def recovery_password_code(email, config, user):
    sender = config.get('MAIL_USERNAME')
    try:
        if not email:
            return jsonify(message='El correo electrónico es obligatorio.'), 400

        email = email.lower().strip()
        code = generate_secure_code()
        now = datetime.now(timezone.utc)  # Siempre en UTC
        hashed = hash_code(code)

        # Elimina códigos previos de verificación para este correo, si existen (previene duplicados)
        VerificationCode.query.filter_by(email=email).delete()

        # Guarda nuevo código hashed
        new_code = VerificationCode(email=email, code=hashed)
        db.session.add(new_code)
        

        # Construcción del correo (recuperación de contraseña)
        subject = 'Recuperación de contraseña - Fiesta Ticket'
        message = (
            f"Hola,\n\n"
            "Has solicitado recuperar la contraseña de tu cuenta en Fiesta Ticket. Si no realizaste esta solicitud, puedes ignorar este mensaje.\n\n"
            f"A continuación tienes el código para restablecer tu contraseña (válido por 10 minutos):\n\n{code}\n\n"
            "Introduce este código en la pantalla de recuperación de contraseña para completar el proceso.\n\n"
            "Si no solicitaste este cambio, te recomendamos revisar la seguridad de tu cuenta.\n\n"
            "Gracias,\nEquipo de Fiesta Ticket"
        )

        msg = Message(subject, sender=sender, recipients=[email])
        msg.body = message

        # Envía el correo
        mail.send(msg)

        user.LastVerificationAttempt = now

        db.session.commit()

        return jsonify(message='Se ha enviado un código de verificación a tu correo electrónico.'), 200

    except Exception as e:
        logging.exception("Error al enviar el correo de verificación")
        db.session.rollback()
        return jsonify(message='Ocurrió un error al enviar el correo de verificación.'), 500

def generate_secure_code():
    return ''.join(secrets.choice('0123456789') for _ in range(6))

def hash_code(code):
    hashed_code = generate_password_hash(code)
    return hashed_code

# Custom exception para manejar los errores de intentos
class TooManyAttemptsError(Exception):
    def __init__(self, message, status_code=429):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

# --- Función check_validation_attempts modificada ---
def check_validation_attempts(email):
    MAX_ATTEMPTS = 5
    BLOCK_WINDOW_MINUTES = 10

    # Consulta los últimos 10 minutos
    recent_attempts = VerificationAttempt.query.filter(
        VerificationAttempt.email == email,
        VerificationAttempt.attempt_time >= datetime.now() - timedelta(minutes=BLOCK_WINDOW_MINUTES)
    ).all()

    # Filtra solo los intentos fallidos (asumiendo que tienes un campo 'success' o similar)
    failed_attempts = [a for a in recent_attempts if not a.success] # Suponiendo un campo 'success' en VerificationAttempt

    if len(failed_attempts) >= MAX_ATTEMPTS:
        raise TooManyAttemptsError('Too many failed attempts. Please retry in a few minutes.', 429)

    return False # Retorna False si no hay suficientes intentos fallidos para bloquear

# Define a regular expression for strong passwords
strong_password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.])[A-Za-z\d@$!%*?&.]{8,}$')