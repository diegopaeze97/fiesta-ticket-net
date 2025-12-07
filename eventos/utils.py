from flask import render_template, jsonify
import requests
import os
import qrcode
from io import BytesIO
from flask_mail import Message
from extensions import mail
from models import EventsUsers, Discounts, PurchasedFeatures
import logging
import uuid
import re
from datetime import datetime, timezone

def sendqr_for_ConfirmedReservationOrFin(inscripcion, config, db, mail, user, Tickets, sale_data):
    try:    
        recipient = user.Email
    
        subject = 'Tu reserva ha sido registrada - Fiesta Ticket'

        msg = Message(subject, sender=config["MAIL_USERNAME"], recipients=[recipient])
        msg_html = render_template('qr_reserva_espectaculo.html', Tickets=Tickets, sale_data=sale_data)
        msg.html = msg_html

        mail.send(msg)
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        #db.session.rollback()   

def sendqr_for_SuccessfulTicketEmission(config, db, mail, user, sale_data, s3, ticket):
    try:
        # Genera un token de VALIDACION DE LA INSCRIPCION

        qr_link = sale_data['link_reserva']

        recipient = user.Email

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        qr_url = update_user_gallery_newQR(img, db, ticket, s3)

        subject = f'Tu Boleto de "{sale_data["event"]}" - Fiesta Ticket'

        msg = Message(subject, sender=config["MAIL_USERNAME"], recipients=[recipient])
        msg_html = render_template('qr_boleto_emitido.html', sale_data=sale_data, qr_image=qr_url)
        msg.html = msg_html

        mail.send(msg)
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def sendqr_for_SuccessfulTicketsEmission(config, mail, user, tickets):
    try:
        for ticket in tickets:
            # Genera un token de VALIDACION DE LA INSCRIPCION

            subject = f'Tu Boleto de "{ticket["event"]}" - Fiesta Ticket'
            recipient = user.Email

            msg = Message(subject, sender=config["MAIL_USERNAME"], recipients=[recipient])
            msg_html = render_template('qr_boleto_emitido.html', sale_data=ticket, qr_image=ticket["qr_image"])
            msg.html = msg_html

            mail.send(msg)

    except Exception as e:
        logging.error(f"Error sending email: {e}")

def sendnotification_for_PaymentStatus(config, db, mail, user, Tickets, sale_data):
    try:
        recipient = user.Email

        if sale_data['status'] == 'rechazado':
            subject = f'Tu abono para {sale_data["event"]} no pudo ser procesado - Fiesta Ticket'
        elif sale_data['status'] == 'aprobado':     
            subject = f'Tu abono para {sale_data["event"]} ha sido aprobado - Fiesta Ticket'
        else:
            subject = f'Tu abono para {sale_data["event"]} esta siendo procesado - Fiesta Ticket'


        msg = Message(subject, sender=config["MAIL_USERNAME"], recipients=[recipient])
        msg_html = render_template('actualizacion_de_status_pago.html', Tickets=Tickets, sale_data=sale_data)
        msg.html = msg_html

        mail.send(msg)
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        #db.session.rollback()   

def sendnotification_for_Blockage(config, db, mail, user, Tickets, sale_data):
    try:
        recipient = user.Email

        subject = f'Tu reserva para {sale_data["event"]} - Fiesta Ticket'

        msg = Message(subject, sender=config["MAIL_USERNAME"], recipients=[recipient])
        msg_html = render_template('actualizacion_de_status_pago.html', Tickets=Tickets, sale_data=sale_data)
        msg.html = msg_html

        mail.send(msg)

        #ahora se notifica a los admins y tiqueteros
        admin_subject = f'Notificación de bloqueo de reserva para {sale_data["event"]} - Fiesta Ticket'

        admins = EventsUsers.query.filter(EventsUsers.role.in_(["admin", "tiquetero"])).all()
        admin_recipients = [admin.Email for admin in admins]

        message_admin = (
            f'🚨 **RESERVA REALIZADA - REQUIERE ATENCIÓN INMEDIATA** 🚨\n\n'
            f'Hola Equipo,\n\n'
            f'Se ha **bloqueado la reserva** (ID de Venta: {sale_data.get("sale_id", "N/A")}) '
            f'del usuario **{user.Email}** para el evento **{sale_data["event"]}**.\n\n'
            f'---\n'
            f'## 👤 Detalles del Usuario\n'
            f'- **Nombre Completo:** {user.FirstName} {user.LastName}\n'
            f'- **Email:** {user.Email}\n'
            f'- **Teléfono:** {user.PhoneNumber or "No registrado"}\n'
            f'- **ID de Cliente:** {user.CustomerID}\n'
            f'---\n'
            f'## 🎫 Detalles de la Reserva\n'
            f'- **Evento:** {sale_data["event"]} ({sale_data["venue"]})\n'
            f'- **Fecha y Hora:** {sale_data["date"]} a las {sale_data["hour"]}\n'
            f'- **Localizador (ID de Venta):** {sale_data.get("localizador", "N/A")} / {sale_data.get("sale_id", "N/A")}\n'
            f'- **Cantidad de Boletos:** {len(Tickets)}\n\n'
            f'---\n'
            f'## 🎟️ Detalles de los Boletos ({len(Tickets)} en total)\n'
        )

        # ----------------------------------------------------
        # Bloque de ITERACIÓN DE TICKETS
        # ----------------------------------------------------
        if Tickets:
            for i, ticket in enumerate(Tickets, 1):
                # Formateo la información de cada ticket
                detalle_ticket = (
                    f'    {i}. ID: {ticket["ticket_id"]} | '
                    f'Sección: {ticket["section"].upper()} | '
                    f'Fila/Número: {ticket["row"]}/{ticket["number"]} | '
                    f'Precio: ${ticket["price"]}\n'
                )
                # Concateno al mensaje principal
                message_admin += detalle_ticket
        # ----------------------------------------------------
        # Bloque de iteracion de addons
        # ----------------------------------------------------
        if sale_data.get("add_ons") and isinstance(sale_data["add_ons"], list):
            message_admin += f'\n---\n## 🎟️ Detalles de los Addons ({len(sale_data["add_ons"])} en total)\n'
            for i, addon in enumerate(sale_data["add_ons"], 1):
                detalle_addon = (
                    f'    {i}. ID: {addon["FeatureID"]} | '
                    f'Nombre: {addon["FeatureName"]} | '
                    f'Cantidad: {addon["Quantity"]} | '
                    f'Precio Unitario: ${addon["FeaturePrice"]} | '
                    f'Total: ${addon["TotalPrice"]}\n'
                )
                message_admin += detalle_addon

        # ----------------------------------------------------
        # Continuación del mensaje
        # ----------------------------------------------------
        message_admin += (
            f'\n---\n'
            f'## 💰 Detalles Financieros\n'
            f'- **Subtotal:** ${sale_data.get("price", "N/A")}\n'
            f'- **Fee:** ${sale_data.get("fee", "N/A")}\n'
            f'- **Descuento:** ${sale_data.get("discount", "N/A")}\n'
            f'- **Total A Pagar:** ${sale_data.get("total_abono", "N/A")}\n'
            f'- **Método de Pago:** {sale_data.get("payment_method", "N/A")}\n'
            f'- **Referencia/Link:** {sale_data.get("reference", "N/A")}\n\n'
            f'---\n'
            f'## 💡 Acción Requerida\n'
            f'Por favor, **Ponte en contacto con el cliente para validar la compra. Si el pago ya fue realizado, ponte en contacto con un administrador para proceder a emitir los boletos\n'
            f'Puedes usar el ID de Venta (`{sale_data.get("sale_id", "N/A")}`) o el Email del cliente (`{user.Email}`) para la búsqueda.\n\n'
            f'Gracias por tu pronta gestión,\n'
            f'**Equipo de Fiesta Ticket**\n'
            f''
        )

        msg_admin = Message(admin_subject, sender=config["MAIL_USERNAME"], recipients=admin_recipients)
        msg_admin.body = message_admin

        mail.send(msg_admin)


    except Exception as e:
        logging.error(f"Error sending email: {e}")
        #db.session.rollback() 

def sendnotification_for_CartAdding(config, db, mail, user, Tickets, event):
    try:

        #ahora se notifica a los admins y tiqueteros
        admin_subject = f'Un usuario agregó a su carrito de compras - Fiesta Ticket'

        admins = EventsUsers.query.filter(EventsUsers.role.in_(["admin", "tiquetero"])).all()
        admin_recipients = [admin.Email for admin in admins]

        message_admin = (
            f'🚨 **Un Usuario ha agregado un item a su carro de compras** 🚨\n\n'
            f'Hola Equipo,\n\n'
            f'Evento **{event.name}**.\n\n'
            f'---\n'
            f'## 👤 Detalles del Usuario\n'
            f'- **Nombre Completo:** {user.FirstName} {user.LastName}\n'
            f'- **Email:** {user.Email}\n'
            f'- **Teléfono:** {user.PhoneNumber or "No registrado"}\n'
            f'- **ID de Cliente:** {user.CustomerID}\n'
            f'---\n'
            f'- **Cantidad de Boletos:** {len(Tickets)}\n\n'
            f'---\n'
            f'## 🎟️ Detalles de los Boletos ({len(Tickets)} en total)\n'
        )

        # ----------------------------------------------------
        # Bloque de ITERACIÓN DE TICKETS
        # ----------------------------------------------------
        if Tickets:
            for i, ticket in enumerate(Tickets, 1):
                # Formateo la información de cada ticket
                detalle_ticket = (
                    f'    {i}. ID: {ticket["ticket_id"]} | '
                    f'Sección: {ticket["section"].upper()} | '
                    f'Fila/Número: {ticket["row"]}/{ticket["number"]} | '
                    f'Precio: ${ticket["price"]/100}\n'
                )
                # Concateno al mensaje principal
                message_admin += detalle_ticket
        else:
            # Caso de contingencia si la lista estuviera vacía por alguna razón
            message_admin += '    (No se pudo recuperar la información detallada de los boletos.)\n'


        msg_admin = Message(admin_subject, sender=config["MAIL_USERNAME"], recipients=admin_recipients)
        msg_admin.body = message_admin

        mail.send(msg_admin)

    except Exception as e:
        logging.error(f"Error sending email: {e}")
        #db.session.rollback()   

def sendnotification_for_CompletedPaymentStatus(config, db, mail, user, Tickets, sale_data):
    try:
        recipient = user.Email

        subject = f'Gracias por tu compra de {sale_data["event"]} - Fiesta Ticket - FACTURA'

        user_data = {
            'full_name': f'{user.FirstName} {user.LastName}',
            'email': user.Email,
            'phone': user.PhoneNumber or 'No registrado',
            'address': user.Address or 'No registrado',
            'identification': user.Identification or 'No registrado'
        }

        template = 'pago_total_realizado.html' if not sale_data.get('is_package_tour') else 'pago_total_realizado_paquetes_turisticos.html'

        msg = Message(subject, sender=config["MAIL_USERNAME"], recipients=[recipient])
        msg_html = render_template(template, Tickets=Tickets, sale_data=sale_data, user_data=user_data)
        msg.html = msg_html

        mail.send(msg)

        subject_admin = f'Notificación de compra completada para {sale_data["event"]} - Fiesta Ticket'

        msg = Message(subject_admin, sender=config["MAIL_USERNAME"], recipients=[config["MAIL_USERNAME"]])
        msg_html = render_template(template, Tickets=Tickets, sale_data=sale_data, user_data=user_data)
        msg.html = msg_html

        mail.send(msg)


    except Exception as e:
        logging.error(f"Error sending email: {e}")
        #db.session.rollback()   

def update_user_gallery_newQR(img, db, ticket, s3):
    S3_BUCKET = "imagenes-fiestatravel"

    try:
        # Convertir a bytes
        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        # Eliminar imagen anterior en S3
        if ticket.QRlink:
            try:
                s3.delete_object(Bucket=S3_BUCKET, Key=ticket.QRlink)
            except Exception as e:
                print(f"Error eliminando {ticket.QRlink}: {e}")

        filename = f"qr_codes/{uuid.uuid4()}.png"

        s3.upload_fileobj(
            buf,
            S3_BUCKET,
            filename,
            ExtraArgs={"ContentType": "image/png"},
        )

        qr_url = f"https://{S3_BUCKET}.s3.amazonaws.com/{filename}"

        # Guardar nuevas fotos en la base de datos respetando el orden
        ticket.QRlink = qr_url
        db.session.commit()

        return qr_url

    except Exception as e:
        logging.error(e)
        return None
    
def newQR(img, ticket, s3):
    S3_BUCKET = "imagenes-fiestatravel"

    try:
        # Convertir a bytes
        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        # Eliminar imagen anterior en S3
        if ticket.QRlink:
            try:
                s3.delete_object(Bucket=S3_BUCKET, Key=ticket.QRlink)
            except Exception as e:
                print(f"Error eliminando {ticket.QRlink}: {e}")

        filename = f"qr_codes/{uuid.uuid4()}.png"

        s3.upload_fileobj(
            buf,
            S3_BUCKET,
            filename,
            ExtraArgs={"ContentType": "image/png"},
        )

        qr_url = f"https://{S3_BUCKET}.s3.amazonaws.com/{filename}"

        return qr_url

    except Exception as e:
        logging.error(e)
        return None
    
def send_ban_notification(email, config):
    sender = config.get('MAIL_USERNAME')
    try:

        email = email.lower().strip()

        # Construcción del correo de notificación de baneo
        subject = 'Notificación de baneo de usuario - Fiesta Ticket'
        message = (
            f"Hola,\n\n"
            "Te informamos que un usuario ha sido baneado del sitio web Fiesta Ticket.\n\n"
            "Si tienes alguna pregunta o necesitas más detalles, por favor contacta al equipo de soporte.\n\n"
            "Gracias,\nEquipo de Fiesta Ticket"
        )

        msg = Message(subject, sender=sender, recipients=[email])
        msg.body = message

        # Envía el correo
        mail.send(msg)

    except Exception as e:
        logging.exception("Error al enviar el correo de verificación")
        #db.session.rollback()

def notify_admins_automatic_pagomovil_verification(config, db, mail, customer, sale, payment, tickets_en_carrito, MontoBS):
    try:
        admin_subject = f'Pago Movil verificado automáticamente - Venta ID {sale.sale_id} - Fiesta Ticket'

        admins = EventsUsers.query.filter(EventsUsers.role.in_(["admin", "tiquetero"])).all()
        admin_recipients = [admin.Email for admin in admins]

        message_admin = (
            f'🚨 **PAGO MOVIL VERIFICADO AUTOMÁTICAMENTE** 🚨\n\n'
            f'Hola Equipo,\n\n'
            f'Se ha **verificado automáticamente un Pago Móvil** (ID de Venta: {sale.sale_id}) '
            f'del usuario **{customer.Email}**.\n\n'
            f'---\n'
            f'## 👤 Detalles del Usuario\n'
            f'- **Nombre Completo:** {customer.FirstName} {customer.LastName}\n'
            f'- **Email:** {customer.Email}\n'
            f'- **Teléfono:** {customer.PhoneNumber or "No registrado"}\n'
            f'- **ID de Cliente:** {customer.CustomerID}\n'
            f'---\n'
            f'## 🎫 Detalles de la Venta\n'
            f'- **Localizador (ID de Venta):** {sale.sale_id}\n'
            f'- **Cantidad de Boletos:** {len(tickets_en_carrito)}\n\n'
            f'---\n'
            f'## 💰 Detalles Financieros\n'
            f'- **Monto Verificado:** ${round(MontoBS/100, 2)}\n'
            f'- **Método de Pago:** Pago Móvil\n\n'
            f'- **Referencia/ID de Transacción:** {payment.Reference}\n'
            f'- **Banco Emisor:** {payment.Bank or "No registrado"}\n'
            f'- **Telefono:** {payment.PhoneNumber or "No registrado"}\n'
            f'---\n'
            f'Gracias por su atención,\n'
            f'**Equipo de Fiesta Ticket**\n'

            f''
        )

        msg_admin = Message(admin_subject, sender=config["MAIL_USERNAME"], recipients=admin_recipients)
        msg_admin.body = message_admin

        mail.send(msg_admin)

    except Exception as e:
        logging.error(f"Error sending email: {e}")
        #db.session.rollback()

def validate_discount_code(discount_code, customer, event_details, tickets_en_carrito, type):
    """
    Valida un código de descuento y devuelve el descuento aplicable.
    """
    #tickets en carrito puede ser una lista de objetos Ticket o diccionarios con 'price' y 'ticket_id'
    tickets = []
    for t in tickets_en_carrito:
        if isinstance(t, dict):
            tickets.append(t)
        else:
            tickets.append({
                'ticket_id': t.ticket_id,
                'ticket_id_provider': t.ticket_id_provider,
                'price': t.price,
                'discount': 0
            })


    if not discount_code:
        return 0, None  # No hay código de descuento
    
    discount_code = discount_code.strip().upper()

    # Use filter_by to avoid passing a tuple into filter() and get a single matching discount
    discount = Discounts.query.filter_by(Code=discount_code).one_or_none()

    if not discount:
        return {"status": False, "message": "Código de descuento inválido"}
    
    if discount.Active == False:
        return {"status": False, "message": "Código de descuento inactivo"}
    
    if discount.UsageLimit and discount.UsedCount >= discount.UsageLimit:
        return {"status": False, "message": "Código de descuento agotado"}
    
    now = datetime.now(timezone.utc).timestamp()

    def _to_timestamp(val):
        if val is None:
            return None
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, datetime):
            # make aware as UTC if naive
            if val.tzinfo is None:
                val = val.replace(tzinfo=timezone.utc)
            return val.timestamp()
        try:
            return float(val)
        except Exception:
            return None

    valid_from_ts = _to_timestamp(discount.ValidFrom)
    if valid_from_ts and valid_from_ts > now:
        return {"status": False, "message": "El código de descuento aún no es válido"}

    valid_to_ts = _to_timestamp(discount.ValidTo)
    if valid_to_ts is None:
        # no valid end date -> treat as expired/not applicable
        return {"status": False, "message": "El código de descuento ha expirado"}

    # extend reservation validity by 600s when not a 'buy' operation
    ValidTo = valid_to_ts if type == 'buy' else valid_to_ts + 600
    if ValidTo < now:
        return {"status": False, "message": "El código de descuento ha expirado"}
    
    if discount.ApplicableEvents:
        applicable_event_ids = [int(eid) for eid in discount.ApplicableEvents.split(',') if eid.isdigit()]
        if event_details.event_id not in applicable_event_ids:
            return {"status": False, "message": "El código de descuento no es aplicable a este evento"}
        
    if discount.ApplicableUsers:
        applicable_user_ids = [int(uid) for uid in discount.ApplicableUsers.split(',') if uid.isdigit()]
        if customer.CustomerID not in applicable_user_ids:
            return {"status": False, "message": "El código de descuento no es aplicable a este usuario"}

    total_discount = 0
    if discount.Percentage:
        for ticket in tickets:
            total_discount += round((discount.Percentage / 100) * ticket["price"], 2)
            total_discount += round((discount.Percentage / 100) * ticket["price"] * (event_details.Fee / 100), 2)
            #actualizamos el discount de cada ticket
            ticket["discount"] = int(round((discount.Percentage / 100) * ticket["price"], 2))

    elif discount.FixedAmount:
        total_discount = int(discount.FixedAmount) 
        # Distribuir el descuento entre los tickets en el carrito
        num_tickets = len(tickets_en_carrito)
        total_price = sum(t["price"] for t in tickets)
        if total_price < total_discount:
            return {"status": False, "message": "El descuento excede el total de la compra"}
        
        if num_tickets > 0:
            for ticket in tickets_en_carrito:
                discount_per_ticket = int(round((ticket["price"] / total_price) * total_discount * (100 - event_details.Fee)/100, 2))
                ticket["discount"] = discount_per_ticket
    else:
        return {"status": False, "message": "Código de descuento inválido"}

    return {"total_discount": total_discount, "tickets": tickets, "status": True, "message": "Código de descuento aplicado exitosamente", "discount_id": discount.DiscountID}

def get_exchange_rate_bsd():
    exchangeRate = 0
    try:
        url_exchange_rate_BsD = f"https://api.dolarvzla.com/public/exchange-rate"

        response_exchange = requests.get(url_exchange_rate_BsD, timeout=20)

        if response_exchange.status_code != 200:
            logging.error(response_exchange.status_code)
            #temporalmente mientras se arregla cloudFlare
            #return {"exchangeRate": 23684}
            return {"message": "No se pudo obtener la tasa de cambio. Por favor, inténtelo de nuevo más tarde."}, 500
        exchange_data = response_exchange.json()
        exchangeRate = exchange_data.get("current", {}).get("usd", 0)

        if exchangeRate <= 200.00: #minimo aceptable al 18 octubre 2025
            return {"message": "Tasa de cambio inválida. Por favor, inténtelo de nuevo más tarde."}, 500
        
        exchangeRate = int(exchangeRate*100)
        return {"exchangeRate": exchangeRate}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error al obtener la tasa de cambio: {str(e)}")
        return {"message": "Error al conectar con el servicio de tasa de cambio."}, 502
    
email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
phone_pattern = re.compile(r'^\+?[1-9]\d{1,14}$')  # E.164 format
cedula_pattern = re.compile(r'^[EV]{1}\d{1,8}$')
venezuelan_phone_pattern = re.compile(r'^(?:0412|0422|0414|0424|0416|0426)\d{7}$')

usd_payment_methods = ['credit_card', 'paypal', 'stripe', 'apple_pay', 'google_pay', 'zelle', 'efectivo']
bsd_payment_methods = ['pagomovil', 'debito_inmediato', 'c2p']

def accepts_all_payment_methods(accepted_payment_methods):
    # 1. Definición de Métodos por Divisa


    if not accepted_payment_methods:
        return 'all'

    # 2. Normalización de la Entrada
    
    # Manejar si la entrada es un string (separado por comas) o una colección (list, tuple, set)
    if isinstance(accepted_payment_methods, str):
        if accepted_payment_methods.strip().lower() == 'all':
            return 'all'
        # Convierte el string separado por comas en una lista de métodos normalizados
        items = [m.strip().lower() for m in accepted_payment_methods.split(',') if m.strip()]
    elif isinstance(accepted_payment_methods, (list, tuple, set)):
        # Convierte la colección en una lista de métodos normalizados
        items = [str(m).strip().lower() for m in accepted_payment_methods if str(m).strip()]
    else:
        # Maneja cualquier otro tipo de entrada
        items = [str(accepted_payment_methods).strip().lower()]

    accepted_set = set(items)

    # 3. Lógica de Decisión
    
    # Opción A: Acepta TODOS los métodos (USD + BSD)
    all_methods = set(usd_payment_methods + bsd_payment_methods)
    if all_methods.issubset(accepted_set):
        return 'all'
    
    # Opción B: Acepta AL MENOS UN método de USD 
    # (Se utiliza 'intersection' para verificar si hay alguna coincidencia)
    if accepted_set.intersection(usd_payment_methods):
        return 'usd'
    
    # Opción C: Acepta AL MENOS UN método de BSD
    # (Se utiliza 'intersection' para verificar si hay alguna coincidencia)
    if accepted_set.intersection(bsd_payment_methods):
        return 'bsd'

    # Opción D: Por defecto (Si acepta algunos, pero no todos los de una categoría completa, o ninguno)
    return 'all'

def get_accepted_payment_methods(tickets_en_carrito):
    accepted_payment_methods = ['all']

    
    for ticket in tickets_en_carrito:
        seat = ticket.seat
        section = seat.section if seat else None

        print(f"Ticket ID: {ticket.ticket_id}, Section Accepted Methods: {section.accepted_payment_methods if section else 'N/A'}")

        if section and section.accepted_payment_methods and section.accepted_payment_methods.lower() != 'all' and accepted_payment_methods == ['all']:
            accepted_payment_methods = section.accepted_payment_methods.lower().split(',') #lista inicial de métodos de pago aceptados

        if section and section.accepted_payment_methods and section.accepted_payment_methods.lower() != 'all' and accepted_payment_methods != []:
            #intersección de métodos de pago aceptados
            accepted_payment_methods = list(set(accepted_payment_methods).intersection(set(section.accepted_payment_methods.lower().split(','))))

    return accepted_payment_methods

def record_purchased_feature(sale_id, feature_id, quantity, price_per_unit):
    purchased_feature = PurchasedFeatures(
        SaleID=sale_id,
        FeatureID=feature_id,
        Quantity=quantity,
        PurchaseAmount=price_per_unit,
    )
    return purchased_feature

def validate_addons(addons, event, payment_method, tickets_en_carrito):
    validated_addons = []

    total_addon_hospedaje = 0
    total_addon_boletos = 0
    
    if not isinstance(addons, list):
        return jsonify({"message": "Formato de complementos inválido"}), 400
    
    addons_ids = []
    
    for addon in addons:
        if not isinstance(addon, dict):
            return jsonify({"message": "ID de complemento inválido"}), 400
        addons_ids.append(int(addon['FeatureID']))
        
    additional_features_obj = event.additional_features

    if not additional_features_obj:
        return jsonify({"message": "No se pueden agregar complementos a este evento"}), 400
    
    total_addon_hospedaje = sum(int(addon.get('Quantity')) for addon in addons if addon.get('FeatureCategory') == 'Hospedaje')
    
    for af in additional_features_obj:
        if af.FeatureID not in addons_ids:
            continue
        if af.Active is False:
            continue
        if af.FeaturePrice < 0:
            continue

        #validamos el metodo de pago:
        accepted_payment_methods_addon = af.accepted_payment_methods.split(',') if af.accepted_payment_methods != 'all' else ['all']

        if 'all' not in accepted_payment_methods_addon and payment_method not in accepted_payment_methods_addon:
            logging.info(f"El método de pago '{payment_method}' no es aceptado para el complemento '{af.FeatureName}'")
            continue

        #ahora validamos la cantidad de cada addon
        quantity = 0 #la mapeamos de addons
        for addon in addons:
            try:
                if int(addon.get('FeatureID')) == int(af.FeatureID):
                    quantity = int(addon.get('Quantity'))
                    break
            except Exception:
                continue

        if quantity < 0 or quantity > 10:
            logging.info("Cantidad de complemento inválida")
            continue
            
        feature = {
            "FeatureID": af.FeatureID,
            "FeatureName": af.FeatureName,
            "FeaturePrice": af.FeaturePrice,
            "FeatureCategory": af.FeatureCategory,
            "Quantity": quantity,
            "TotalPrice": round(quantity * af.FeaturePrice / 100, 2)
        }

        if af.FeatureCategory == 'Hospedaje':
            total_addon_hospedaje += quantity
        if af.FeatureCategory == 'Boletos de concierto':
            total_addon_boletos += quantity

        validated_addons.append(feature)

    # Validar que no se exceda el límite de hospedaje
    if total_addon_boletos > len(tickets_en_carrito) and total_addon_boletos > total_addon_hospedaje:
        return jsonify({"message": "No puedes agregar más complementos de boletos de concierto que boletos comprados"}), 400
    
    if len(validated_addons) != len(addons_ids):
        return jsonify({"message": "Uno o más complementos inválidos"}), 400
    
    return validated_addons
