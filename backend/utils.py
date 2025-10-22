from flask import render_template
import os
import qrcode
from io import BytesIO
from flask_mail import Message
from extensions import db, mail
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

        qr_url = update_user_gallery(img, db, ticket, s3)

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

def update_user_gallery(img, db, ticket, s3):
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