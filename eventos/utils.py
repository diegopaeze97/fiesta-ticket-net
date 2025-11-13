from flask import render_template
import os
import qrcode
from io import BytesIO
from flask_mail import Message
from extensions import db, mail
from models import EventsUsers
import logging
import uuid
import re

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
        print(f"QR Link: {qr_link}")

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
            f'- **Monto Total de la Venta:** ${sale_data.get("total_abono", "N/A")}\n'
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

        msg = Message(subject, sender=config["MAIL_USERNAME"], recipients=[recipient])
        msg_html = render_template('pago_total_realizado.html', Tickets=Tickets, sale_data=sale_data)
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
    
email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
phone_pattern = re.compile(r'^\+?[1-9]\d{1,14}$')  # E.164 format
cedula_pattern = re.compile(r'^[EV]{1}\d{1,8}$')
venezuelan_phone_pattern = re.compile(r'^(?:0412|0422|0414|0424|0416|0426)\d{7}$')