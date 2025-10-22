from functools import wraps
from flask import jsonify, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from jwt import ExpiredSignatureError, InvalidTokenError  # de PyJWT
import logging

def optional_roles(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            g.has_access = False
            try:
                verify_jwt_in_request(optional=True)
                claims = get_jwt()

                if claims and "role" in claims and claims["role"] in roles:
                    g.has_access = True

            except ExpiredSignatureError:
                # Token expirado → tratar como público
                g.has_access = False
            except InvalidTokenError:
                # Token inválido o en blacklist
                g.has_access = False
            except Exception:
                # cualquier otro problema → también público
                g.has_access = False

            return fn(*args, **kwargs)
        return wrapper
    return decorator

def roles_required(allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            try:
                verify_jwt_in_request()  # Verifica si el token está presente y es válido
                claims = get_jwt()
                current_user_role = claims.get('role')
                current_user_status = claims.get('status')

                print(current_user_role)

                # Manejo específico para 'unverified customer'
                if current_user_status == 'unverified':
                    return jsonify({
                        'status': 'error',
                        'message': 'Account not verified',
                        'redirect': '/verify-email'
                    }), 403 # Usamos 403 Forbidden ya que no tiene el rol permitido completo

                if current_user_role not in allowed_roles:
                    logging.warning(f"⚠️ Unauthorized access attempt by user with role: {current_user_role}. Allowed roles: {allowed_roles}")
                    return jsonify({
                        'status': 'error',
                        'message': 'Unauthorized role',
                        'redirect': '/signin'
                    }), 403 

                return fn(*args, **kwargs)

            except ExpiredSignatureError:
                logging.warning("⚠️ JWT token has expired.")
                return jsonify({
                    'status': 'error',
                    'message': 'Token has expired',
                    'redirect': '/signin'
                }), 401 # 401 Unauthorized for expired tokens
            except InvalidTokenError:
                logging.warning("⚠️ Invalid JWT token.")
                return jsonify({
                    'status': 'error',
                    'message': 'Token is invalid',
                    'redirect': '/signin'
                }), 401 # 401 Unauthorized for invalid tokens
            except Exception as e:
                logging.error(f"❌ Unexpected error in roles_required: {e}", exc_info=True)
                return jsonify({'message': 'An unexpected error occurred'}), 500 # Un error 500 genérico para errores internos
        return decorated_function
    return decorator