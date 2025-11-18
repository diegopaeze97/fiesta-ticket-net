from flask import render_template
from io import BytesIO
from flask_mail import Message
from extensions import db, mail
import logging
from botocore.exceptions import BotoCoreError, ClientError
from weasyprint import HTML, CSS
import os

def generate_pdf_with_weasyprint(liquidation, event, sales, totals, discounts, additional_charges, payment, comments, sections):
    # 1) Renderiza el HTML usando la plantilla (la plantilla ahora contiene el @page correcto)
    html = render_template(
        'liquidation_template.html',
        liquidation=liquidation,
        sales=sales,
        event=event,
        totals=totals,
        discounts=discounts,
        additionalCharges=additional_charges,
        payment=payment,
        comments=comments,
        sections=sections
    )

    # 2) Convierte el HTML a PDF. No vuelvas a declarar @page aquí para evitar conflictos.
    pdf = HTML(string=html).write_pdf(
        stylesheets=[
            CSS(string='''
                /* Solo estilos globales mínimos aquí; deja @page en el template */
                body { font-family: "Helvetica Neue", Arial, sans-serif; }
            ''')
        ]
    )

    return pdf


def upload_to_s3_private(s3, bucket, key, data, content_type='application/pdf'):
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=data, ContentType=content_type, ACL='private')
        return True
    except (BotoCoreError, ClientError) as e:
        logging.error(f"Error subiendo a S3: {e}")
        return False
    
def upload_to_s3_public(s3, bucket, key, data, content_type):
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=data, ContentType=content_type)
        return (f"https://{bucket}.s3.amazonaws.com/{key}")
    except (BotoCoreError, ClientError) as e:
        logging.error(f"Error subiendo a S3: {e}")
        return None


def send_email_with_attachment(sender, recipients, attachment_bytes, attachment_filename):
    """
    Envía un correo con attachment usando flask-mail. Devuelve True/False.
    """
    if not recipients:
        logging.warning("No hay destinatarios para el correo.")
        return False

    if isinstance(recipients, str):
        recipients = [recipients]

    subject = "Liquidación de evento - Fiesta Ticket"
    body_text = (
        "Estimado/a productor/a,\n\n"
        "Adjunto encontrará en formato PDF la liquidación correspondiente. El documento contiene información detallada, "
        "incluyendo la moneda utilizada, el detalle de la transferencia o pago, y el desglose por cada venta y por cada boleto vendido.\n\n"
        "Puede ingresar a la plataforma de Fiesta Ticket con sus credenciales para consultar los detalles de todas sus liquidaciones.\n\n"
        "Atentamente,\nEquipo Fiesta Ticket"
    )

    try:
        msg = Message(subject, sender=sender, recipients=recipients)
        msg.body = body_text

        # Adjuntar el archivo (PDF por defecto)
        content_type = 'application/pdf'
        msg.attach(attachment_filename, content_type, attachment_bytes)

        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Error enviando correo con adjunto vía Flask-Mail: {e}")
        return False