from flask import jsonify
from datetime import timedelta, datetime, timezone
import logging
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import or_
from extensions import db, stripe, mail, s3
from models import EventsUsers, Ticket, Seat, Sales, Payments, Logs
from flask_mail import Message
from sqlalchemy.orm import joinedload, load_only
import requests
import os
import eventos.utils as utils_eventos


def handle_checkout_completed(data, config):
    """
    Handles the 'checkout.session.completed' webhook event from Stripe.
    """
    session = data 
    
    if session.get('mode') != 'payment':
        logging.info(f"Skipping checkout.session.completed event as it's not a payment mode.")
        return

    user_id = session.get("metadata", {}).get("customer_id")
    tickets_ids_str = session.get("metadata", {}).get("tickets")
    event_id = session.get("metadata", {}).get("event_id")

    if not user_id or user_id == "None":
        logging.warning("⚠️ No user_id found in metadata for checkout session.")
        return
    
    if not tickets_ids_str:
        logging.warning(f"⚠️ No tickets found in metadata for user {user_id} in checkout session.")
        return
    
    if not event_id:
        logging.warning(f"⚠️ No event_id found in metadata for user {user_id} in checkout session.")
        return
    try:

        tickets_ids = []

        if '|' in tickets_ids_str:
            tickets_ids = [int(tid) for tid in tickets_ids_str.split('|') if tid]
        else:
            tickets_ids = [int(tickets_ids_str)]

        tickera_id = config.get('FIESTATRAVEL_TICKERA_USERNAME', '')
        tickera_api_key = config.get('FIESTATRAVEL_TICKERA_API_KEY', '')

        # ----------------------------------------------------------------
        # 1️⃣ Validaciones iniciales
        # ----------------------------------------------------------------
        if not all([tickera_id, tickera_api_key]):
            return jsonify({"message": "Faltan parámetros obligatorios"}), 400

        # ----------------------------------------------------------------
        # 3️⃣ Validar cliente
        # ----------------------------------------------------------------
        customer = EventsUsers.query.options(
            load_only(EventsUsers.CustomerID, EventsUsers.status)
        ).filter_by(CustomerID=int(user_id)).one_or_none()
        if not customer:
            return jsonify({"message": "Usuario no encontrado"}), 404

        if customer.status.lower() == "suspended":
            return jsonify({"message": "Su cuenta está suspendida."}), 403

        # ----------------------------------------------------------------
        # 4️⃣ Obtener tickets en carrito
        # ----------------------------------------------------------------
        # Validar que event_id sea numérico antes de convertirlo a int
        if not str(event_id).isdigit():
            return jsonify({"message": "ID de evento inválido"}), 400

        # Limitar columnas cargadas con load_only para Ticket (import local)

        tickets_en_carrito = Ticket.query.options(
            load_only(
            Ticket.ticket_id,
            Ticket.customer_id,
            Ticket.status,
            Ticket.expires_at,
            Ticket.ticket_id_provider,
            Ticket.price,
            Ticket.discount,
            Ticket.fee,
            Ticket.sale_id,
            Ticket.saleLink,
            Ticket.saleLocator,
            Ticket.availability_status,
            Ticket.emission_date,
            ),
            joinedload(Ticket.seat).load_only(
            Seat.row,
            Seat.number,
            ).joinedload(Seat.section),
            joinedload(Ticket.event)
        ).filter(
            Ticket.ticket_id.in_(tickets_ids),
        ).all()

        if not tickets_en_carrito:
            return jsonify({"message": "No hay tickets en el carrito"}), 404

        event = tickets_en_carrito[0].event
        if not event or not event.active:
            sendnotification_checkout_failed(config, db, mail, customer, tickets_en_carrito, event, session)
            return jsonify({"message": "Evento no encontrado o inactivo"}), 404

        now = datetime.now(timezone.utc)  # Siempre en UTC
        Tickets = []
        for t in tickets_en_carrito:
            ticket = {
                'ticket_id': t.ticket_id,
                'row': t.seat.row,
                'number': t.seat.number,
                'section': t.seat.section.name,
                'event': t.price,
                'price': round(t.price / 100, 2)
            }
            Tickets.append(ticket)
            if t.customer_id != int(user_id):
                if t.status == 'en_carrito':
                    # 1. Convierte t.expires_at a aware ASUMIENDO que es UTC
                    if t.expires_at and t.expires_at.tzinfo is None:
                        expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
                    else:
                        expires_at_aware = t.expires_at # Ya tiene info de zona horaria
                    if not expires_at_aware or expires_at_aware < now:
                        sendnotification_checkout_failed(config, db, mail, customer, tickets_en_carrito, event, session)
                        return jsonify({"message": "Tu reserva ha caducado"}), 400
            if t.status == 'pagado':
                sendnotification_checkout_failed(config, db, mail, customer, tickets_en_carrito, event, session)
                return jsonify({"message": "Alguno de los tickets ya fue comprado"}), 400
            


        # ----------------------------------------------------------------
        # 5️⃣ Bloquear en Tickera (antes de modificar BD local)
        # ----------------------------------------------------------------
        url_block = f"{config['FIESTATRAVEL_API_URL']}/eventos_api/block-tickets"
        payload = {
            "event": event.event_id_provider,
            "tickets": [
                {"ticket_id_provider": t.ticket_id_provider, "price": t.price}
                for t in tickets_en_carrito
            ],
            "tickera_id": tickera_id,
            "tickera_api_key": tickera_api_key,
            "type_of_sale": "user_sale"
        }

        try:
            response_block = requests.post(url_block, json=payload, timeout=30)
            response_block.raise_for_status()
        except Exception as e:
            sendnotification_checkout_failed(config, db, mail, customer, Tickets, event, session)
            logging.error(f"Error bloqueando tickets en Tickera: {str(e)}")
            return jsonify({"message": "Error bloqueando tickets en Productora"}), 502

        # ----------------------------------------------------------------
        # 6️⃣ Aplicar cambios locales (una sola transacción)
        # ----------------------------------------------------------------
        total_price = sum(t.price for t in tickets_en_carrito)
        total_fee = sum(round((event.Fee or 0) * t.price / 100, 2) for t in tickets_en_carrito)
        ticket_str_ids = '|'.join(str(t.ticket_id) for t in tickets_en_carrito)

        received = session.get('amount_total', 0)  # en centavos

        serializer = config['serializer']
        token = serializer.dumps({'user_id': user_id})
        qr_link = f'{config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={token}'
        localizador = os.urandom(3).hex().upper()

        # Crear registro de venta
        sale = Sales(
            ticket_ids=ticket_str_ids,
            price=total_price,
            paid=received,
            user_id=user_id,
            status='pagado',
            created_by=user_id,
            StatusFinanciamiento='decontado',
            event=event.event_id,
            fee=total_fee,
            discount=0,
            saleLink = token,
            saleLocator = localizador
            
        )
        db.session.add(sale)
        db.session.flush()

        # Actualizar tickets
        for t in tickets_en_carrito:
            t.status = 'pagado'
            t.customer_id = int(user_id)
            t.sale_id = sale.sale_id
            t.expires_at = None

        today = datetime.utcnow().date()

        # Use Stripe's payment_intent (fallback to session id) as the payment reference
        payment_reference = session.get('payment_intent') or session.get('id')

        payment = Payments(
            SaleID=sale.sale_id,
            Amount=received,
            PaymentDate=today,
            PaymentMethod='Stripe',
            Reference=payment_reference,
            Status='aprobado',
            CreatedBy=user_id,
        )
        db.session.add(payment)
        db.session.flush()

        # ----------------------------------------------------------------
        # 7️⃣ Enviar notificación según método de pago
        # ---------------------------------------------------------------


        # ⚠️ Evitar autoflush prematuro que causa EOF detected
        with db.session.no_autoflush:

            log_for_abono = Logs(
                UserID=user_id,
                Type='abono',
                Timestamp=datetime.now(),
                Details=f"Abono de {payment.Amount} aprobado para la venta {payment.sale.sale_id}",
                SaleID=payment.sale.sale_id
            )
            db.session.add(log_for_abono)

            reserva_link = f'{config["WEBSITE_FRONTEND_TICKERA"]}/reservas?query={payment.sale.saleLink}'
            

            # ---------------------------------------------------------------
            # 7️⃣ Llamar a la API para calcular la tasa en bolivares BCV
            # ---------------------------------------------------------------
            url_exchange_rate_BsD = f"https://api.dolarvzla.com/public/exchange-rate"

            response_exchange = requests.get(url_exchange_rate_BsD, timeout=20)
            exchangeRate = 0

            if response_exchange.status_code != 200:
                logging.error(response_exchange.status_code)
                sendnotification_checkout_failed(config, db, mail, customer, Tickets, event, session)
                return jsonify({"message": "No se pudo obtener la tasa de cambio. Por favor, inténtelo de nuevo más tarde."}), 500
            exchange_data = response_exchange.json()
            exchangeRate = exchange_data.get("current", {}).get("usd", 0)

            if exchangeRate <= 200.00: #minimo aceptable al 18 octubre 2025
                sendnotification_checkout_failed(config, db, mail, customer, Tickets, event, session)
                return jsonify({"message": "Tasa de cambio inválida. Por favor, inténtelo de nuevo más tarde."}), 500
            
            exchangeRate = int(exchangeRate*100)

            for ticket in tickets_en_carrito:

                ticket.status = 'pagado'
                ticket.availability_status = 'Listo para canjear'
                ticket.emission_date = datetime.now().date()

                log_for_emision = Logs(
                    UserID=user_id,
                    Type='emision de boleto',
                    Timestamp=datetime.now(),
                    Details=f"Emisión de boleto {ticket.ticket_id} para la venta {payment.sale.sale_id}",
                    SaleID=payment.sale.sale_id,
                    TicketID=ticket.ticket_id
                )
                db.session.add(log_for_emision)

                serializer = config['serializer']
                token = serializer.dumps({'ticket_id': ticket.ticket_id, 'sale_id': payment.sale.sale_id})
                localizador = os.urandom(3).hex().upper()

                ticket.saleLink = token
                ticket.saleLocator = localizador

                qr_link = f'{config["WEBSITE_FRONTEND_TICKERA"]}/tickets?query={token}'

                sale_data = {
                    'row': ticket.seat.row,
                    'number': ticket.seat.number,
                    'section': ticket.seat.section.name,
                    'event': ticket.event.name,
                    'venue': ticket.event.venue.name,
                    'date': ticket.event.date_string,
                    'hour': ticket.event.hour_string,
                    'price': round(ticket.price / 100, 2),
                    'discount': round(ticket.discount / 100, 2),
                    'fee': round(ticket.fee / 100, 2),
                    'total': round((ticket.price + ticket.fee - ticket.discount) / 100, 2),
                    'link_reserva': qr_link,
                    'localizador': localizador
                }

                utils_eventos.sendqr_for_SuccessfulTicketEmission(config, db, mail, customer, sale_data, s3, ticket)

            IVA = config.get('IVA_PERCENTAGE', 0) / 100
            amount_with_IVA = received * IVA / (1 + IVA)
            IVA_amount = received - amount_with_IVA

            sale_data = {
                'sale_id': str(payment.sale.sale_id),
                'event': payment.sale.event_rel.name,
                'venue': payment.sale.event_rel.venue.name,
                'date': payment.sale.event_rel.date_string,
                'hour': payment.sale.event_rel.hour_string,
                'price': round(payment.sale.price*exchangeRate / 10000, 2),
                'iva_amount': round(IVA_amount*exchangeRate / 10000, 2),
                'net_amount': round(amount_with_IVA*exchangeRate / 10000, 2),
                'total_abono': round(received*exchangeRate / 10000, 2),
                'payment_method': 'Tarjeta de Crédito',
                'payment_date': today.strftime('%d-%m-%Y'),
                'reference': payment_reference,
                'link_reserva': reserva_link,
                'localizador': payment.sale.saleLocator,
                'exchange_rate_bsd': round(exchangeRate/100, 2),
                'status': 'aprobado',
                'title': 'Tu pago ha sido procesado exitosamente',
                'subtitle': 'Gracias por tu compra, a continuación encontrarás los detalles de tu factura'
            }
            utils_eventos.sendnotification_for_CompletedPaymentStatus(config, db, mail, customer, Tickets, sale_data)
        db.session.commit()

        return jsonify({"message": "Tickets bloqueados y venta registrada exitosamente", "status": "ok"}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        sendnotification_checkout_failed(config, db, mail, customer, Tickets, event, session)
        logging.error(f"❌ Database error processing checkout.session.completed for user {user_id}: {e}", exc_info=True)
    except Exception as e:
        sendnotification_checkout_failed(config, db, mail, customer, Tickets, event, session)
        logging.error(f"❌ Unexpected error in handle_checkout_completed for user {user_id}: {e}", exc_info=True)


def sendnotification_checkout_failed(config, db, mail, user, Tickets, event, session):
    try:
        # Asunto del correo
        admin_subject = f'⚠️ Fallo en el proceso de pago para {user.FirstName} {user.LastName} - Fiesta Ticket'

        # Buscar destinatarios (admins y tiqueteros)
        admins = EventsUsers.query.filter(EventsUsers.role.in_(["admin", "tiquetero"])).all()
        admin_recipients = [admin.Email for admin in admins]

        # Cuerpo del mensaje
        message_admin = (
            f'🚨 **PAGO FALLIDO - REQUIERE REVISIÓN** 🚨\n\n'
            f'Hola equipo,\n\n'
            f'Se detectó un **fallo en el intento de pago**'
            f'del usuario **{user.Email}** para el evento **{event.name}**.\n\n'
            f'El sistema no recibió confirmación de Stripe o los boletos fueron liberados antes de tiempo, por lo que **los boletos permanecen sin procesar o fueron liberados automáticamente**.\n\n'
            f'---\n'
            f'## 👤 Detalles del Usuario\n'
            f'- **Nombre Completo:** {user.FirstName} {user.LastName}\n'
            f'- **Email:** {user.Email}\n'
            f'- **Teléfono:** {user.PhoneNumber or "No registrado"}\n'
            f'- **ID de Cliente:** {user.CustomerID}\n'
            f'---\n'
            f'## 🎟️ Intento de Compra\n'
            f'- **Evento:** {event.name}\n'
            f'- **Cantidad de Boletos Intentados:** {len(Tickets)}\n\n'
            f'---\n'
            f'## 🎟️ Detalles de los Boletos ({len(Tickets)} en total)\n'
        )

        # Iterar sobre los tickets si existen
        if Tickets:
            for i, ticket in enumerate(Tickets, 1):
                detalle_ticket = (
                    f'    {i}. ID: {ticket.ticket_id} | '
                    f'Sección: {ticket.seat.section.name} | '
                    f'Fila/Número: {ticket.seat.row}/{ticket.seat.number} | '
                    f'Precio: ${round(ticket.price/100, 2)}\n'
                )
                message_admin += detalle_ticket
        else:
            message_admin += '    (No se pudo recuperar la información de los boletos.)\n'

        # Continuar con los detalles financieros
        message_admin += (
            f'\n---\n'
            f'## 💰 Detalles del Pago\n'
            f'- **Monto Total Intentado:** ${round(session.get('amount_total', 0)/100, 2)}\n'
            f'- **Método de Pago:** Tarjeta de credito / Stripe\n'
            f'- **Referencia/Link Stripe:** {session.get('payment_intent') or session.get('id')}\n\n'
            f'---\n'
            f'## 🧾 Notas del Sistema\n'
            f'- El intento de pago fue rechazado, cancelado o no confirmado dentro del tiempo límite.\n'
            f'- Los boletos asociados a esta reserva **no fueron emitidos**.\n\n'
            f'---\n'
            f'## 💡 Acción Recomendada\n'
            f'Por favor, revisa el estado del pago en el panel de administración o en Stripe.\n'
            f'Gracias por tu atención,\n'
            f'**Equipo de Fiesta Ticket**\n'
        )

        # Crear y enviar correo
        msg_admin = Message(admin_subject, sender=config["MAIL_USERNAME"], recipients=admin_recipients)
        msg_admin.body = message_admin

        mail.send(msg_admin)

    except Exception as e:
        logging.error(f"Error sending checkout failed email: {e}")
        db.session.rollback()
