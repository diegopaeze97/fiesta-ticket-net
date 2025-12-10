import logging
from flask import jsonify
from models import EventsUsers
from extensions import db
import eventos.utils as utils

def update_user_info(user_id, codigo_pais, phone, identification, address): #esta funcion se usa para llenar informacion faltante en el perfil de usuario, principaplemnte cuando crea la cuenta con social login
    try:
         # Validación de datos de entrada

        user = db.session.query(EventsUsers).filter_by(CustomerID=user_id).one_or_none()

        if user is None:
            return jsonify({'status': 'error', 'message': 'Usuario no encontrado.'}), 404
        
        if not phone or not identification or not address or not codigo_pais:
            return jsonify({'status': 'error', 'message': 'Todos los campos son obligatorios.'}), 400
            
        if codigo_pais:
            if not utils.country_code_pattern.match(codigo_pais):
                return jsonify({'status': 'error', 'message': 'Código de país no válido. Debe estar en formato E.164.'}), 400
            
        if phone:
            if not utils.phone_pattern.match(phone):
                return jsonify({'status': 'error', 'message': 'Número de teléfono no válido. Debe estar en formato E.164.'}), 400
            
        if identification:
            if not utils.cedula_pattern.match(identification.upper()):
                return jsonify({'status': 'error', 'message': 'Numero de cedula invalido'}), 400
            
        user.CountryCode = codigo_pais if not user.CountryCode else user.CountryCode
        user.PhoneNumber = phone if not user.PhoneNumber else user.PhoneNumber
        user.Identification = identification if not user.Identification else user.Identification
        user.Address = address if not user.Address else user.Address

        return jsonify({'status': 'ok', 'message': 'Información actualizada correctamente.'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al actualizar la información personal: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error al actualizar la información.'}), 500