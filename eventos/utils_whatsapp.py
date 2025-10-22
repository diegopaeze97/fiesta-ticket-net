
from flask import jsonify
import logging
import requests

def send_new_sale_notification(config, customer, tickets_en_carrito, sale_data, full_phone_number):
    tickera_id = config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
    tickera_api_key = config.get('FIESTATRAVEL_TICKERA_API_KEY', '')
    url_block = f"{config['FIESTATRAVEL_API_URL']}/whatsapp/new_sale_notification"

    customer_data = {
        "FirstName": customer.FirstName,
        "LastName": customer.LastName,
        "Email": customer.Email,
        "Phone": full_phone_number if full_phone_number else customer.PhoneNumber,
    }

    payload = {
        "customer_data": customer_data,
        "tickets_data": tickets_en_carrito,
        "tickera_id": tickera_id,
        "tickera_api_key": tickera_api_key,
        "sale_data": sale_data
    }

    try:
        response_block = requests.post(url_block, json=payload, timeout=30)
        response_block.raise_for_status()
    except Exception as e:
        logging.error(f"Error notificando a usuarios: {str(e)}")
        return jsonify({"message": "Error notificando a usuarios"}), 502
    
    logging.info(f"Respuesta de notificacion en Tickera: {response_block.json()}")
    
    return response_block.json()