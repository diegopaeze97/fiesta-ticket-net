from flask import render_template, current_app
from flask_mail import Message
from extensions import mail
from models import EventsUsers
import logging
from weasyprint import HTML, CSS


def generate_seller_liquidation_pdf(payment, seller, sales_data, totals, additional_charges, discounts, comments):
    """
    Genera un PDF con el resumen de la liquidación del vendedor.
    Retorna bytes del PDF generado.
    """
    try:
        # Helper functions para formatear moneda
        def format_currency(value, symbol="$", decimals=2):
            try:
                v = float(value or 0)
            except Exception:
                return str(value)
            return f"{symbol}{v:,.{decimals}f}"

        def format_currency_bsd(value, symbol="BsD", decimals=2):
            try:
                v = float(value or 0)
            except Exception:
                return str(value)
            return f"{symbol}{v:,.{decimals}f}"

        def format_currency_cents_to_dollars(value, symbol="$", decimals=2):
            try:
                v = float((value or 0) / 100)
            except Exception:
                return str((value or 0) / 100)
            return f"{symbol}{v:,.{decimals}f}"

        # Registrar filtros en Jinja
        current_app.jinja_env.filters['currency'] = format_currency
        current_app.jinja_env.filters['currency_bsd'] = format_currency_bsd
        current_app.jinja_env.filters['currency_cents_to_dollars'] = format_currency_cents_to_dollars

        # Renderizar HTML
        html = render_template(
            'seller_liquidation_template.html',
            payment=payment,
            seller=seller,
            sales_data=sales_data,
            totals=totals,
            additional_charges=additional_charges,
            discounts=discounts,
            comments=comments
        )

        # Convertir a PDF
        pdf = HTML(string=html).write_pdf(
            stylesheets=[
                CSS(string='''
                    body { font-family: "Helvetica Neue", Arial, sans-serif; }
                ''')
            ]
        )

        return pdf
    except Exception as e:
        logging.error(f"Error generando PDF de liquidación de vendedor: {e}")
        raise


def send_seller_liquidation_notification(config, seller, payment, pdf_bytes, totals, sale_count):
    """
    Envía notificación por correo al vendedor cuando se procesa su liquidación.
    Incluye el PDF adjunto.
    """
    try:
        recipient = seller.Email
        sender = config.get("MAIL_USERNAME")

        if not recipient or not sender:
            logging.error("No se pudo enviar email: falta remitente o destinatario")
            return False

        subject = f'Liquidación de comisiones procesada - Fiesta Ticket'

        # Formatear montos
        commission_amount = totals.get("totalCommission", 0)
        final_amount = totals.get("finalAmount", 0)
        currency = payment.Currency or "USD"
        
        # Crear mensaje en texto plano
        body_text = f"""
Estimado/a {seller.FirstName} {seller.LastName},

Te informamos que se ha procesado una liquidación de tus comisiones de ventas.

📊 RESUMEN DE LA LIQUIDACIÓN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Número de ventas liquidadas: {sale_count}
• Comisión total: ${commission_amount:.2f} {currency}
• Monto final a recibir: ${final_amount:.2f} {currency}
• Método de pago: {payment.PaymentMethod}
• Referencia: {payment.Reference}
• Fecha de pago: {payment.PaymentDate.strftime('%Y-%m-%d') if payment.PaymentDate else 'N/A'}

💰 DETALLES DEL PAGO:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
El pago se realizará o se ha realizado mediante {payment.PaymentMethod}.
"""

        if payment.Currency == "bolivares" and payment.AmountBS:
            amount_bs = payment.AmountBS / 100
            body_text += f"\nMonto en Bolívares: BsD {amount_bs:,.2f}\n"

        body_text += f"""
Adjunto encontrarás un PDF con el desglose completo de la liquidación, 
incluyendo el detalle de cada venta y la información de los boletos vendidos.

Puedes ingresar a tu panel de vendedor en Fiesta Ticket para consultar 
el historial de tus ventas y comisiones.

Si tienes alguna pregunta sobre esta liquidación, no dudes en contactarnos.

Atentamente,
Equipo Fiesta Ticket
"""

        msg = Message(subject, sender=sender, recipients=[recipient])
        msg.body = body_text

        # Adjuntar PDF
        attachment_filename = f"liquidacion_vendedor_{payment.PaymentID}.pdf"
        msg.attach(attachment_filename, 'application/pdf', pdf_bytes)

        mail.send(msg)
        logging.info(f"Notificación de liquidación enviada al vendedor {seller.Email}")
        return True

    except Exception as e:
        logging.error(f"Error enviando notificación al vendedor: {e}")
        return False


def send_admin_liquidation_notification(config, seller, payment, pdf_bytes, totals, sale_count, sale_ids):
    """
    Envía notificación por correo a los administradores cuando se procesa una liquidación.
    Incluye el PDF adjunto.
    """
    try:
        sender = config.get("MAIL_USERNAME")
        
        # Obtener admins
        admins = EventsUsers.query.filter(EventsUsers.role.in_(["admin", "super_admin"])).all()
        admin_recipients = [admin.Email for admin in admins if admin.Email]

        if not admin_recipients:
            logging.warning("No hay administradores para notificar")
            return False

        if not sender:
            logging.error("No se pudo enviar email: falta remitente")
            return False

        subject = f'Nueva liquidación procesada para vendedor - Fiesta Ticket'

        # Formatear montos
        commission_amount = totals.get("totalCommission", 0)
        charges = totals.get("totalCharges", 0)
        discounts_total = totals.get("totalDiscounts", 0)
        final_amount = totals.get("finalAmount", 0)
        currency = payment.Currency or "USD"

        # Crear mensaje en texto plano
        body_text = f"""
🔔 NUEVA LIQUIDACIÓN PROCESADA

Hola Equipo Administrativo,

Se ha procesado una nueva liquidación de comisiones para un vendedor.

👤 INFORMACIÓN DEL VENDEDOR:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Nombre: {seller.FirstName} {seller.LastName}
• Email: {seller.Email}
• ID de Vendedor: {seller.CustomerID}

📊 RESUMEN DE LA LIQUIDACIÓN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• ID de Pago: {payment.PaymentID}
• Número de ventas: {sale_count}
• IDs de ventas liquidadas: {', '.join(map(str, sale_ids[:10]))}{'...' if len(sale_ids) > 10 else ''}
• Comisión total: ${commission_amount:.2f} {currency}
• Cargos adicionales: ${charges:.2f} {currency}
• Descuentos aplicados: ${discounts_total:.2f} {currency}
• Monto final pagado: ${final_amount:.2f} {currency}

💰 DETALLES DEL PAGO:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Método de pago: {payment.PaymentMethod}
• Referencia: {payment.Reference}
• Fecha de pago: {payment.PaymentDate.strftime('%Y-%m-%d') if payment.PaymentDate else 'N/A'}
• Moneda: {currency}
"""

        if payment.Currency == "bolivares" and payment.AmountBS:
            amount_bs = payment.AmountBS / 100
            body_text += f"• Monto en Bolívares: BsD {amount_bs:,.2f}\n"

        if payment.Comments:
            body_text += f"\n📝 COMENTARIOS:\n{payment.Comments}\n"

        body_text += """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Adjunto encontrarás el PDF con el desglose completo de la liquidación.

Atentamente,
Sistema Fiesta Ticket
"""

        msg = Message(subject, sender=sender, recipients=admin_recipients)
        msg.body = body_text

        # Adjuntar PDF
        attachment_filename = f"liquidacion_vendedor_{payment.PaymentID}.pdf"
        msg.attach(attachment_filename, 'application/pdf', pdf_bytes)

        mail.send(msg)
        logging.info(f"Notificación de liquidación enviada a administradores")
        return True

    except Exception as e:
        logging.error(f"Error enviando notificación a administradores: {e}")
        return False


def upload_pdf_to_s3_public(s3, bucket, key, pdf_bytes):
    """
    Sube un PDF a S3 y retorna la URL pública.
    """
    try:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=pdf_bytes,
            ContentType='application/pdf'
        )
        url = f"https://{bucket}.s3.amazonaws.com/{key}"
        logging.info(f"PDF subido exitosamente a S3: {url}")
        return url
    except Exception as e:
        logging.error(f"Error subiendo PDF a S3: {e}")
        return None
