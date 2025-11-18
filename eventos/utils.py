from flask import render_template
import os
import qrcode
from io import BytesIO
from flask_mail import Message
from extensions import db, mail
from models import EventsUsers, Discounts
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
        db.session.rollback()   

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
        db.session.rollback()   

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
        else:
            # Caso de contingencia si la lista estuviera vacía por alguna razón
            message_admin += '    (No se pudo recuperar la información detallada de los boletos.)\n'

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
        db.session.rollback()   

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

        msg = Message(subject, sender=config["MAIL_USERNAME"], recipients=[recipient])
        msg_html = render_template('pago_total_realizado.html', Tickets=Tickets, sale_data=sale_data, user_data=user_data)
        msg.html = msg_html

        mail.send(msg)

        subject_admin = f'Notificación de compra completada para {sale_data["event"]} - Fiesta Ticket'

        msg = Message(subject_admin, sender=config["MAIL_USERNAME"], recipients=[config["MAIL_USERNAME"]])
        msg_html = render_template('pago_total_realizado.html', Tickets=Tickets, sale_data=sale_data, user_data=user_data)
        msg.html = msg_html

        mail.send(msg)


    except Exception as e:
        logging.error(f"Error sending email: {e}")
        db.session.rollback()   

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
    
email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
phone_pattern = re.compile(r'^\+?[1-9]\d{1,14}$')  # E.164 format
cedula_pattern = re.compile(r'^[EV]{1}\d{1,8}$')
venezuelan_phone_pattern = re.compile(r'^(?:0412|0422|0414|0424|0416|0426)\d{7}$')