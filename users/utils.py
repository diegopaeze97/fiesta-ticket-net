import logging
from flask import jsonify
from models import EventsUsers
from extensions import db
import eventos.utils as utils

def update_user_info(user_id, firstname, lastname, codigo_pais, phone, identification, address, missing_fields_behavior):
    try:
         # Validación de datos de entrada

        user = db.session.query(EventsUsers).filter_by(CustomerID=user_id).one_or_none()

        if user is None:
            return jsonify({'status': 'error', 'message': 'Usuario no encontrado.'}), 404
        
        if missing_fields_behavior != 'ignore':
            # Validar que los campos no estén vacíos
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
            
        user.FirstName = firstname if firstname else user.FirstName
        user.LastName = lastname if lastname else user.LastName
        user.CountryCode = codigo_pais if codigo_pais else user.CountryCode
        user.PhoneNumber = phone
        user.Identification = identification
        user.Address = address if address else user.Address

        return jsonify({'status': 'ok', 'message': 'Información actualizada correctamente.'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error al actualizar la información personal: {e}")
        return jsonify({'status': 'error', 'message': 'Ocurrió un error al actualizar la información.'}), 500