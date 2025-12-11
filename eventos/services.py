import logging
from flask import jsonify
from models import EventsUsers, Ticket, Seat, Event, Logs, Discounts
from extensions import db, mail, s3
import os
import qrcode
from sqlalchemy import update, func
from sqlalchemy.orm import joinedload
import eventos.utils as utils
from datetime import datetime, timezone

def bvc_api_verification_success(config, tickets_en_carrito, payment, customer, discount_code, validated_addons, total_price_addons):

    try:
        total_discount = payment.sale.discount
        total_price = payment.sale.price - total_price_addons

        # Validar que total_price no sea cero para evitar división por cero
        if not total_price or total_price == 0:
            return {"message": "Error: el precio total de la venta no puede ser cero", "status": "error"}

        tickets = []

        for ticket in tickets_en_carrito:
            discount = 0

            if total_discount > 0:
                proportion = ticket.price / total_price
                discount = int(round(total_discount * proportion, 2))

            log_for_emision = Logs(
                UserID=customer.CustomerID,
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

            qr_link = f'{config["WEBSITE_FRONTEND_TICKERA"]}/tickets?query={token}'

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_link)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")

            qr_url = utils.newQR(img, ticket, s3)

            ticket.status = 'pagado'
            ticket.availability_status = 'Listo para canjear'
            ticket.emission_date = datetime.now().date()
            ticket.discount = discount
            ticket.saleLink = token
            ticket.saleLocator = localizador
            ticket.QRlink = qr_url # Guardar nuevas fotos en la base de datos respetando el orden

            sale_data = {
                'row': ticket.seat.row,
                'number': ticket.seat.number,
                'section': ticket.seat.section.name,
                'event': ticket.event.name,
                'venue': ticket.event.venue.name,
                'date': ticket.event.date_string,
                'hour': ticket.event.hour_string,
                'price': round(ticket.price / 100, 2),
                'discount': round(discount / 100, 2),
                'fee': round(ticket.fee / 100, 2),
                'total': round((ticket.price + ticket.fee - discount) / 100, 2),
                'link_reserva': qr_link,
                'localizador': localizador,
                'qr_image': qr_url
            }
            tickets.append(sale_data)
            
        IVA = config.get('IVA_PERCENTAGE', 0) / 100
        amount_no_IVA = int(round(payment.Amount / (1 + (IVA)/100), 2))
        amount_IVA = payment.Amount - amount_no_IVA
        BsDexchangeRate = customer.BsDExchangeRate
        total_fee = payment.sale.fee
        amount_discount = payment.sale.discount
        currency = 'bsd'

        sale_data = {
            'sale_id': str(payment.sale.sale_id),
            'event': payment.sale.event_rel.name,
            'venue': payment.sale.event_rel.venue.name,
            'date': payment.sale.event_rel.date_string,
            'hour': payment.sale.event_rel.hour_string,
            'price': round(payment.sale.price*BsDexchangeRate / 10000, 2) if currency == 'bsd' else round(payment.sale.price / 100, 2),
            'iva_amount': round(amount_IVA*BsDexchangeRate / 10000, 2) if currency == 'bsd' else round(amount_IVA / 100, 2),
            'net_amount': round(amount_no_IVA*BsDexchangeRate / 10000, 2) if currency == 'bsd' else round(amount_no_IVA / 100, 2),
            'total_abono': round(payment.Amount*BsDexchangeRate / 10000, 2) if currency == 'bsd' else round(payment.Amount / 100, 2),
            'payment_method': payment.PaymentMethod,
            'payment_date': payment.PaymentDate.strftime('%d-%m-%Y'),
            'reference': payment.Reference or 'N/A',
            'link_reserva': payment.sale.saleLink,
            'localizador': payment.sale.saleLocator,
            'exchange_rate_bsd': round(BsDexchangeRate/100, 2),
            'status': 'aprobado',
            'title': 'Tu pago ha sido procesado exitosamente',
            'subtitle': 'Gracias por tu compra, a continuación encontrarás los detalles de tu factura',
            'is_package_tour': payment.sale.event_rel.type_of_event == 'paquete_turistico',
            'currency': currency,
            'add_ons': validated_addons if validated_addons else None,
        }

        discount_code = discount_code.upper() if discount_code else None

        if discount_code:
            discount = Discounts.query.filter(Discounts.Code == discount_code).one_or_none()

        if discount:
            # Actualizar uso del descuento
            discount.UsedCount = (discount.UsedCount or 0) + 1
            payment.sale.discount_ref = discount.DiscountID

    
        # Actualizar métricas del evento
        stmt = (
            update(Event)
            .where(Event.event_id == int(payment.sale.event_rel.event_id))
            .values(
                total_sales = func.coalesce(Event.total_sales, 0) + 1,
                gross_sales = func.coalesce(Event.gross_sales, 0) + (int(payment.Amount) if payment.Amount is not None else 0),
                total_fees  = func.coalesce(Event.total_fees, 0) + (int(total_fee) if total_fee is not None else 0),
                total_discounts = func.coalesce(Event.total_discounts, 0) + (int(amount_discount) if amount_discount is not None else 0),
                total_discounts_tickera = (
                    func.coalesce(Event.total_discounts_tickera, 0)
                    + ((func.coalesce(Event.Fee, 0) * int(amount_discount) / 100) if amount_discount is not None else 0)
                )
            )
            .returning(Event.event_id)  # opcional, útil para confirmar
        )

        db.session.execute(stmt)

        db.session.commit()

        if payment.sale.event_rel.type_of_event == 'espectaculo':
            utils.sendqr_for_SuccessfulTicketsEmission(config, mail, customer, tickets)
        
        utils.sendnotification_for_CompletedPaymentStatus(config, db, mail, customer, tickets, sale_data)

        return {"message": "Métricas del evento actualizadas exitosamente", "status": "ok", "tickets": tickets}

    except Exception as e:
        # En caso de cualquier error (ej. la tabla fue bloqueada brevemente)
        logging.error(f"Error al actualizar métricas del evento: {e}")
        db.session.rollback() 
        return {"error": f"Fallo al actualizar DB: {e}", "status": "error"}


def preprocess_validation(user_id, event_id, addons, discount_code, payment_method):
    try:
        # ----------------------------------------------------------------
        # 3️⃣ Validar cliente
        # ----------------------------------------------------------------
        customer = EventsUsers.query.filter_by(CustomerID=int(user_id)).one_or_none()
        if not customer:
            logging.info("Usuario no encontrado")
            return jsonify({"message": "Usuario no encontrado", 'status': 'error'}), 404

        if customer.status.lower() == "suspended":
            logging.info("Cuenta suspendida")
            return jsonify({"message": "Su cuenta está suspendida.", 'status': 'error'}), 403

        if customer.status.lower() != "verified":
            logging.info("Cuenta no verificada")
            return jsonify({"message": "Su cuenta no está verificada.", 'status': 'error'}), 403

        # ----------------------------------------------------------------
        # 4️⃣ Obtener tickets en carrito
        # ----------------------------------------------------------------
        # Validate event_id is numeric and convert to int
        if not str(event_id).isdigit():
            logging.info("ID de evento inválido")
            return jsonify({"message": "ID de evento inválido", 'status': 'error'}), 400
        event_id_int = int(event_id)

        tickets_en_carrito = Ticket.query.options(
            joinedload(Ticket.seat).joinedload(Seat.section),
            joinedload(Ticket.event)
        ).filter(
            Ticket.customer_id == customer.CustomerID,
            Ticket.status == 'en carrito',
            Ticket.event_id == event_id_int
        ).all()

        if not tickets_en_carrito:
            logging.info("No hay tickets en el carrito")
            return jsonify({"message": "No hay tickets en el carrito", 'status': 'error'}), 404


        if len(tickets_en_carrito) > 6:
            logging.info("No se pueden comprar más de 6 boletos a la vez")
            return jsonify({"message": "No se pueden comprar más de 6 boletos a la vez", 'status': 'error'}), 400

        event = tickets_en_carrito[0].event

        if not event or not event.active:
            logging.info("Evento no encontrado o inactivo")
            return jsonify({"message": "Evento no encontrado o inactivo", 'status': 'error'}), 404

        accepted_payment_methods = utils.get_accepted_payment_methods(tickets_en_carrito)
        payment_method = payment_method.lower()

        if payment_method not in accepted_payment_methods and 'all' not in accepted_payment_methods:
            logging.info("El método de pago seleccionado no está disponible para los asientos en el carrito")
            return jsonify({"message": "El método de pago seleccionado no está disponible para los asientos en el carrito", 'status': 'error'}), 400
        
        # ----------------------------------------------------------------
        # 2️⃣ Validar addons
        # ----------------------------------------------------------------
        
        validated_addons = []
        total_price_addons = 0
        
        if addons:
            
            validation_response = utils.validate_addons(addons, event, payment_method, tickets_en_carrito)
            if isinstance(validation_response, tuple):  # Si es una respuesta de error
                logging.info(validation_response)
                return validation_response  # Retorna el error directamente
            
            validated_addons = validation_response

        # ----------------------------------------------------------------
        # 3️⃣ Calcular totales y preparar datos para Stripe
        # ----------------------------------------------------------------
        
        total_discount = 0
        discount_id = None
        ### validamos el descuento
        if discount_code:
            discount_validation = utils.validate_discount_code(discount_code, customer, event, tickets_en_carrito, 'buy')
            if not discount_validation.get('status'):
                logging.info("Código de descuento inválido")
                return jsonify({"message": discount_validation.get('message', 'Error en el descuento'), 'status': 'error'}), 400
            else:
                total_discount = discount_validation.get('total_discount', 0)
                discount_id = discount_validation.get('discount_id')
        
        tickets_list = []
        tickets_ids = ""
        total_price_tickets = 0

        now = datetime.now(timezone.utc)  # Siempre en UTC
        for t in tickets_en_carrito:
            # 1. Convierte t.expires_at a aware ASUMIENDO que es UTC
            if t.expires_at and t.expires_at.tzinfo is None:
                expires_at_aware = t.expires_at.replace(tzinfo=timezone.utc)
            else:
                expires_at_aware = t.expires_at # Ya tiene info de zona horaria
            if not expires_at_aware or expires_at_aware < now:
                logging.info("Una o más reservas han caducado")
                return jsonify({"message": "Tu reserva ha caducado", 'status': 'error'}), 400
            
            seat = t.seat
            section = seat.section if seat else None

            section_name = (section.name.lower().replace(' ', '') if section else "sinseccion")
            row_name = seat.row if seat and seat.row else "sinfila"
            number = (seat.number if seat and seat.number else "sinnumero")

            tickets_ids += f"{t.ticket_id}|"

            total_price_tickets += t.price

            tickets_list.append({
                "section": section_name,
                "price": t.price,
                "seat": f"{row_name}{number}",
            })

        total_price_addons= sum(addon['FeaturePrice'] * addon['Quantity'] for addon in validated_addons)

        total_fee = (event.Fee or 0) * total_price_tickets / 100
        total_fee_int = int(total_fee)

        tickets_ids = tickets_ids[:-1]  # Elimina el último "|"

        if total_discount > (total_price_tickets + total_fee):
            total_discount = total_price_tickets + total_fee

        total_price = int(total_price_tickets) + int(total_price_addons)
        total_amount_to_pay = int(total_price + total_fee_int - total_discount)

        return {
            "customer": customer,
            "event": event,
            "tickets": tickets_list,
            "tickets_en_carrito": tickets_en_carrito,
            "tickets_ids": tickets_ids,
            "total_price": total_price,
            "total_price_tickets": total_price_tickets,
            "total_price_addons": total_price_addons,
            "total_amount_to_pay": total_amount_to_pay,
            "total_fee": total_fee_int,
            "total_discount": total_discount,
            "validated_addons": validated_addons,
            "discount_id": discount_id
        }
    except Exception as e:
        logging.error(f"Error en preprocess_validation: {e}")
        return jsonify({"message": "Ocurrió un error inesperado.", 'status': 'error'}), 500
    
def ticket_approval_c2p(tickets_en_carrito, total_discount, total_price, validated_addons, payment, customer, config, discount_code):

    tickets = []
    total_price_addons = 0
    try:
        if validated_addons:
            for addon in validated_addons:
                    purchased_feature = utils.record_purchased_feature(
                        payment.sale.sale_id,
                        int(addon["FeatureID"]),
                        int(addon["Quantity"]),
                        int(addon["FeaturePrice"])
                    )
                    db.session.add(purchased_feature)
                    total_price_addons += int(addon["Quantity"]) * int(addon["FeaturePrice"])

        for ticket in tickets_en_carrito:
            discount = 0

            if total_discount > 0:
                proportion = ticket.price / total_price
                discount = int(round(total_discount * proportion, 2))

            log_for_emision = Logs(
                UserID=customer.CustomerID,
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

            qr_link = f'{config["WEBSITE_FRONTEND_TICKERA"]}/tickets?query={token}'

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_link)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")

            qr_url = utils.newQR(img, ticket, s3)

            ticket.status = 'pagado'
            ticket.sale_id = payment.sale.sale_id
            ticket.expires_at = None
            ticket.availability_status = 'Listo para canjear'
            ticket.emission_date = datetime.now().date()
            ticket.discount = discount
            ticket.saleLink = token
            ticket.saleLocator = localizador
            ticket.QRlink = qr_url # Guardar nuevas fotos en la base de datos respetando el orden

            sale_data = {
                'row': ticket.seat.row,
                'number': ticket.seat.number,
                'section': ticket.seat.section.name.replace('20_ ', ' '),
                'event': ticket.event.name,
                'venue': ticket.event.venue.name,
                'date': ticket.event.date_string,
                'hour': ticket.event.hour_string,
                'price': round(ticket.price / 100, 2),
                'discount': round(discount / 100, 2),
                'fee': round(ticket.fee / 100, 2),
                'total': round((ticket.price + ticket.fee - discount) / 100, 2),
                'link_reserva': qr_link,
                'localizador': localizador,
                'qr_image': qr_url
            }
            tickets.append(sale_data)
            
        IVA = config.get('IVA_PERCENTAGE', 0) / 100
        amount_no_IVA = int(round(payment.Amount / (1 + (IVA)/100), 2))
        amount_IVA = payment.Amount - amount_no_IVA
        BsDexchangeRate = customer.BsDExchangeRate
        total_fee = payment.sale.fee
        amount_discount = payment.sale.discount
        currency = 'bsd'

        sale_data = {
            'sale_id': str(payment.sale.sale_id),
            'event': payment.sale.event_rel.name,
            'venue': payment.sale.event_rel.venue.name,
            'date': payment.sale.event_rel.date_string,
            'hour': payment.sale.event_rel.hour_string,
            'price': round(payment.sale.price*BsDexchangeRate / 10000, 2) if currency == 'bsd' else round(payment.sale.price / 100, 2),
            'iva_amount': round(amount_IVA*BsDexchangeRate / 10000, 2) if currency == 'bsd' else round(amount_IVA / 100, 2),
            'net_amount': round(amount_no_IVA*BsDexchangeRate / 10000, 2) if currency == 'bsd' else round(amount_no_IVA / 100, 2),
            'total_abono': round(payment.Amount*BsDexchangeRate / 10000, 2) if currency == 'bsd' else round(payment.Amount / 100, 2),
            'payment_method': payment.PaymentMethod,
            'payment_date': payment.PaymentDate,
            'reference': payment.Reference or 'N/A',
            'link_reserva': payment.sale.saleLink,
            'localizador': payment.sale.saleLocator,
            'exchange_rate_bsd': round(BsDexchangeRate/100, 2),
            'status': 'aprobado',
            'title': 'Tu pago ha sido procesado exitosamente',
            'subtitle': 'Gracias por tu compra, a continuación encontrarás los detalles de tu factura',
            'is_package_tour': payment.sale.event_rel.type_of_event == 'paquete_turistico',
            'currency': currency,
            'add_ons': validated_addons if validated_addons else None,
        }

        discount_code = discount_code.upper() if discount_code else None

        if discount_code:
            discount = Discounts.query.filter(Discounts.Code == discount_code).one_or_none()

        if discount:
            # Actualizar uso del descuento
            discount.UsedCount = (discount.UsedCount or 0) + 1
            payment.sale.discount_ref = discount.DiscountID


        # Actualizar métricas del evento
        stmt = (
            update(Event)
            .where(Event.event_id == int(payment.sale.event_rel.event_id))
            .values(
                total_sales = func.coalesce(Event.total_sales, 0) + 1,
                gross_sales = func.coalesce(Event.gross_sales, 0) + (int(payment.Amount) if payment.Amount is not None else 0),
                total_fees  = func.coalesce(Event.total_fees, 0) + (int(total_fee) if total_fee is not None else 0),
                total_discounts = func.coalesce(Event.total_discounts, 0) + (int(amount_discount) if amount_discount is not None else 0),
                total_discounts_tickera = (
                    func.coalesce(Event.total_discounts_tickera, 0)
                    + ((func.coalesce(Event.Fee, 0) * int(amount_discount) / 100) if amount_discount is not None else 0)
                )
            )
            .returning(Event.event_id)  # opcional, útil para confirmar
        )

        db.session.execute(stmt)

        if payment.sale.event_rel.type_of_event == 'espectaculo':
            utils.sendqr_for_SuccessfulTicketsEmission(config, mail, customer, tickets)
        
        utils.sendnotification_for_CompletedPaymentStatus(config, db, mail, customer, tickets, sale_data)

        return jsonify({"message": "Métricas del evento actualizadas exitosamente", "status": "ok"})
    except Exception as e:
        logging.exception(f"Error en validate-c2p tickets: {e}")
        return jsonify({
            "status": "error",
            "message": "Error interno al validar transacción",
            "detail": str(e)
        }), 500

