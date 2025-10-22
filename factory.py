from flask import Flask, jsonify
from flask_session import Session
import os
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer as Serializer
#rutas 
from eventos.routes import events
from users.routes import users
from backend.routes import backend
from extensions import jwt, db, socketio, mail # para importar flask_jwt_extended, db, jwt, SQLAlchemy
from models import Revoked_tokens
from flask_cors import CORS



def createApp():

    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET')
    app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET')
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10080)  

    serializer = Serializer(app.config['SECRET_KEY'], salt='reset_password')
    app.config['serializer'] = serializer # Almacena el serializer en la aplicación Flask

    db_username = os.environ.get('POSTGRES_USERNAME')
    db_password = os.environ.get('POSTGRES_PASSWORD')
    db_name = os.environ.get('POSTGRES_DB')
    db_url = os.environ.get('POSTGRES_URL')

    #app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_username}:{db_password}@{db_url}/{db_name}?sslmode=require&options=endpoint%3Dtight-boat-07037648'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_username}:{db_password}@{db_url}/{db_name}?sslmode=require'
    #app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_username}:{db_password}@{db_url}/{db_name}'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_recycle': 280,
        'pool_pre_ping': True
    }

    # Configura Flask-Session
    app.config['SESSION_TYPE'] = 'filesystem'  # Puedes usar otras opciones de almacenamiento
    app.config['SESSION_COOKIE_SECURE'] = True  # Hace que la cookie sea segura (solo en HTTPS)
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Hace que la cookie sea HTTP-only
    app.config['SESSION_USE_SIGNER'] = True  # Firma la cookie para mayor seguridad

    # Configura Flask-Mail
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')  # Servidor SMTP de tu proveedor de correo
    app.config['MAIL_PORT'] = os.environ.get('MAIL_PORT')  # Puerto de correo SMTP
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Tu dirección de correo
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # Tu contraseña
    app.config['MAIL_USE_TLS'] = True  # Usar TLS (True o False según corresponda)
    app.config['MAIL_USE_SSL'] = False  # Usar SSL (True o False según corresponda)
    app.config['IMGUR_CLIENT_ID'] = os.environ.get('IMGUR_CLIENT_ID')
    app.config['IMGUR_CLIENT_SECRET'] = os.environ.get('IMGUR_CLIENT_SECRET')

    # Credenciales de API de Fiesta Ticket
    app.config['FIESTATRAVEL_TICKERA_USERNAME'] = os.environ.get('FIESTATRAVEL_TICKERA_USERNAME')
    app.config['FIESTATRAVEL_TICKERA_API_KEY'] = os.environ.get('FIESTATRAVEL_TICKERA_API_KEY')
    app.config['FIESTATRAVEL_API_URL'] = os.environ.get('FIESTATRAVEL_API_URL')
    
    #taxes 
    app.config['IVA_PERCENTAGE'] = int(os.environ.get('IVA_PERCENTAGE', 0))  # Porcentaje de impuestos, por defecto 0 si no está definido

    #apis
    app.config['rapidapi_key'] = os.environ.get('rapidapi_key') 

    # Configura Monday
    app.config['monday_accessToken'] = os.getenv('monday_accessToken') 

    # Configura whatsapp
    app.config['WHA_SECURITY_TOKEN'] = os.getenv('WHA_SECURITY_TOKEN') 
    app.config['WHATSAPP_TOKEN'] = os.getenv('WHATSAPP_TOKEN') 
    app.config['whatsapp_url'] = os.getenv('whatsapp_url') 

    app.config['WEBSITE_FRONTEND_TICKERA'] = os.getenv('WEBSITE_FRONTEND_TICKERA')

        # Configurar GoogleSheets
    # Cargar las credenciales desde el archivo JSON
    import json
    with open('la-fiesta-del-golf-app-4364c8ea2c28.json', 'r') as f:
        google_creds = json.load(f)

    app.config['google_sheets_credentials'] = google_creds
    app.config['google_sheet_id'] = os.getenv('google_sheet_id') 

    db.init_app(app)
    jwt.init_app(app)
    socketio.init_app(app)
    mail.init_app(app)
    Session(app)

    cors_origins = os.environ.get('CORS_ORIGINS', '*')
    origins_list = [origin.strip() for origin in cors_origins.split(',')]
    CORS(
        app, 
        origins=origins_list, 
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], 
        allowed_headers=["Content-Type", "Authorization"],
        supports_credentials=True
    )

    #hay que chequear si el usuario tiene bloqueos

    @jwt.user_identity_loader
    def user_identity_lookup(identity):
        return identity  # Asegura que siempre retorne el ID

    # Manejar errores de autorización
    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        return jsonify({
            'status': 'error',
            'message': 'Missing authorization token',
            'redirect': '/signin'  # El cliente debe manejar esta redirección
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(reason):
        return jsonify({
            'status': 'error',
            'message': 'Invalid token: ' + reason,
            'redirect': '/signin'
        }), 422

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'status': 'error',
            'message': 'Token has expired',
            'redirect': '/signin'
        }), 401

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        return is_token_revoked(jwt_payload)

    def is_token_revoked(decoded_token):
        token_jti = decoded_token["jti"]
        revoked = db.session.query(Revoked_tokens).filter_by(tokens=token_jti).first()
        return revoked is not None

    # Este loader maneja específicamente tokens revocados
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'status': 'error',
            'message': 'Token has been revoked',
            'redirect': '/signin'
        }), 401


    app.register_blueprint(events, url_prefix='/events')
    app.register_blueprint(backend, url_prefix='/backend')
    app.register_blueprint(users, url_prefix='/users')

    return app
