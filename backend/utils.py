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
    
def generate_tickets_pdf(customer, event_data, tickets_data):
    """
    Genera un PDF con todos los tickets de una venta.
    Retorna bytes del PDF generado.
    """
    from flask import render_template, current_app
    from weasyprint import HTML, CSS
    import logging

    try:
        # Helper functions para formatear moneda
        def format_currency(value, symbol="$", decimals=2):
            try:
                v = float(value or 0)
            except Exception:
                return str(value)
            return f"{symbol}{v:,.{decimals}f}"

        # Registrar filtros en Jinja si no existen
        if 'currency' not in current_app.jinja_env.filters:
            current_app.jinja_env.filters['currency'] = format_currency

        # Renderizar HTML
        html = render_template(
            'tickets_pdf_template.html',
            customer=customer,
            event=event_data,
            tickets=tickets_data,
            total_tickets=len(tickets_data)
        )

        # Convertir a PDF
        pdf = HTML(string=html).write_pdf(
            stylesheets=[
                CSS(string='''
                    @page {
                        size: A4;
                        margin: 1cm;
                    }
                    body { 
                        font-family: "Helvetica Neue", Arial, sans-serif; 
                        font-size: 12px;
                    }
                    .ticket-container {
                        page-break-inside: avoid;
                        margin-bottom: 20px;
                        border: 2px solid #333;
                        border-radius: 10px;
                        padding: 15px;
                    }
                    .qr-code {
                        width: 150px;
                        height: 150px;
                    }
                ''')
            ]
        )

        return pdf
    except Exception as e:
        logging.error(f"Error generando PDF de tickets: {e}")
        raise

def send_tickets_email(config, customer, event_data, tickets_data, pdf_bytes):
    """
    Envía un email al cliente con todos sus tickets adjuntos en PDF.
    """
    from flask import render_template
    from flask_mail import Message
    from extensions import mail
    import logging

    try:
        recipient = customer.Email
        sender = config.get("MAIL_USERNAME")

        if not recipient or not sender:
            logging.error("No se pudo enviar email: falta remitente o destinatario")
            raise ValueError("Falta remitente o destinatario")

        subject = f'Tus entradas para {event_data["name"]} - Fiesta Ticket'

        # Crear mensaje HTML
        html_content = render_template(
            'resend_tickets_email.html',
            customer=customer,
            event=event_data,
            tickets=tickets_data,
            total_tickets=len(tickets_data)
        )

        # Crear mensaje en texto plano como fallback
        body_text = f"""
¡Hola {customer.FirstName}!

Te reenviamos tus entradas para el evento:

🎭 EVENTO: {event_data['name']}
📍 LUGAR: {event_data['venue']}
📅 FECHA: {event_data['date']}
🕐 HORA: {event_data['hour']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 RESUMEN DE TUS ENTRADAS ({len(tickets_data)} en total):

"""
        for i, ticket in enumerate(tickets_data, 1):
            body_text += f"""
Entrada #{i}
• Sección: {ticket['section']}
• Fila: {ticket['row']} | Asiento: {ticket['number']}
• Localizador: {ticket['localizador']}
• Link: {ticket['ticket_link']}
"""

        body_text += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📎 Adjunto encontrarás un PDF con todos tus tickets y códigos QR.

⚠️ IMPORTANTE:
• Presenta tu código QR en la entrada del evento
• Puedes mostrar el QR desde tu celular o imprimirlo
• Cada entrada es válida para una sola persona

Si tienes alguna pregunta, no dudes en contactarnos.

¡Te esperamos en el evento!

Atentamente,
Equipo Fiesta Ticket
"""

        msg = Message(subject, sender=sender, recipients=[recipient])
        msg.body = body_text
        msg.html = html_content

        # Adjuntar PDF
        attachment_filename = f"entradas_{event_data['name'].replace(' ', '_')}_{event_data['sale_locator']}.pdf"
        # Limpiar nombre de archivo de caracteres especiales
        attachment_filename = "".join(c for c in attachment_filename if c.isalnum() or c in ('_', '-', '.'))
        msg.attach(attachment_filename, 'application/pdf', pdf_bytes)

        mail.send(msg)
        logging.info(f"Tickets reenviados exitosamente a {recipient}")
        return True

    except Exception as e:
        logging.error(f"Error enviando email de tickets: {e}")
        raise