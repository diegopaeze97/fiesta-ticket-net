from flask import request, jsonify, Blueprint, make_response, session, current_app, g
from flask_jwt_extended import create_access_token,  set_access_cookies, jwt_required, verify_jwt_in_request
from werkzeug.security import  check_password_hash, generate_password_hash
from extensions import db, s3
from models import EventsUsers, Revoked_tokens, Event, Venue, Section, Seat, Ticket, Liquidations, Sales, Logs, Payments, EventUserAccess, Providers
from flask_jwt_extended import get_jwt, get_jti
from flask_mail import Message
import logging
from sqlalchemy.orm import joinedload, load_only
from sqlalchemy import and_, or_, func, case
import os
import bleach
import pandas as pd
from datetime import datetime, timedelta, timezone
import eventos.utils as utils
from extensions import mail
from decorators.utils import optional_roles, roles_required
import signup.utils as signup_utils
import eventos.utils_whatsapp as WA_utils
import requests

from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import backend.utils as utils_backend

providers = Blueprint('providers', __name__)

@providers.route('/load-dashboard', methods=['GET'])
@roles_required(allowed_roles=["provider"])
def load_dashboard():
    user_id = get_jwt().get("id")
    if user_id is None:
        return jsonify({'status': 'error', 'message': 'Usuario no autenticado.'}), 401

    if not user_id:
        return jsonify({'status': 'error', 'message': 'Usuario no autenticado.'}), 401

    try:
        # Aseguramos que user_id sea int (según tu esquema)
        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            return jsonify({'status': 'error', 'message': 'ID de usuario inválido.'}), 400

        # Consultamos usando join en la tabla de asociación para filtrar correctamente
        events = (
            Event.query
            .join(EventUserAccess, Event.event_id == EventUserAccess.event_id)
            .options(
                joinedload(Event.venue).load_only(Venue.name),
                joinedload(Event.tickets).load_only(Ticket.status, Ticket.emission_date, Ticket.ticket_id, Ticket.price),
            )
            .filter(
                EventUserAccess.user_id == user_id,
            )
            .all()
        )

        events_data = []
        total_liquidado = 0
        gross_sales = 0
        total_tickets_sold = 0
        tickets = []

        for event in events:
            # Usa los nombres de columnas reales: event_id, liquidado, gross_sales, etc.
            events_data.append({
                'EventID': event.event_id,
                'Name': event.name,
                'Venue': event.venue.name if event.venue else None,
                'Date': event.date_string,
                'Hour': event.hour_string,
            })

            total_liquidado += (event.liquidado or 0)
            gross_sales += (getattr(event, 'gross_sales', 0) or 0)

            # Contar tickets pagados. Si tienes muchos tickets considera hacer un COUNT en BD
            if event.tickets:
                for t in event.tickets:
                    if getattr(t, 'status', None) == 'pagado':
                        tickets.append({
                            'TicketID': getattr(t, 'ticket_id', None),
                            'EmissionDate': getattr(t, 'emission_date', None),
                            'Price': round((getattr(t, 'price', 0) or 0) / 100, 2),
                        })
                        total_tickets_sold += 1


        stats = {
            'total_events': len(events),
            'total_liquidated': total_liquidado/100,
            'gross_sales': gross_sales/100,
            'total_tickets_sold': total_tickets_sold,
        }

        return jsonify({'status': 'success', 'events': events_data, 'stats': stats, 'tickets': tickets}), 200

    except Exception as e:
        logging.exception("Error cargando dashboard")  # incluye traceback
        return jsonify({'status': 'error', 'message': 'Ocurrió un error interno. Intenta nuevamente.'}), 500

    finally:
        db.session.close()

@providers.route('/load-liquidations', methods=['GET'])
@roles_required(allowed_roles=["provider"])
def load_liquidations():
    event_param = request.args.get('id_event', '')
    user_id = get_jwt().get("id")

    if not event_param:
        return jsonify({'message': 'faltan parámetros', 'status': 'error'}), 400

    try:
        # validar ids
        try:
            event_id = int(event_param)
        except (TypeError, ValueError):
            return jsonify({'message': 'id_event inválido', 'status': 'error'}), 400

        try:
            user_id = int(user_id) if user_id is not None else None
        except (TypeError, ValueError):
            return jsonify({"message": "ID de usuario inválido", "status": "error"}), 400

        # Verificar acceso: el user debe tener un EventUserAccess válido o ser el proveedor dueño del evento
        if user_id is None:
            return jsonify({"message": "Usuario no autenticado", "status": "error"}), 401

        has_access = db.session.query(EventUserAccess).filter(
            EventUserAccess.event_id == event_id,
            EventUserAccess.user_id == user_id,
        ).first() is not None

        # Si no tiene acceso por la tabla de asociación, permitir si es el proveedor asociado al evento
        if not has_access:
            ev_check = db.session.query(Event).filter(Event.event_id == event_id, Event.event_provider == user_id).first()
            if not ev_check:
                return jsonify({"message": "No se encontró el evento o no tienes permisos", "status": "error"}), 404

        # --- AGREGACIONES en DB para totales ---
        # Contar tickets vendidos (join Sales -> Ticket) y contar tickets incluidos en liquidaciones (sale.liquidado)
        # Sumar montos de ventas (price - discount + fee) para totales y para montos liquidados
        sums_query = (
            db.session.query(
                func.coalesce(func.count(Ticket.ticket_id), 0).label('total_tickets_sold'),
                # CORRECCIÓN: case() en SQLAlchemy 1.4+/2.0 espera whens como elementos posicionales, no como lista.
                func.coalesce(func.sum(case((Sales.liquidado == True, 1), else_=0)), 0).label('total_tickets_liquidated'),
                func.coalesce(func.sum((func.coalesce(Sales.price, 0) - func.coalesce(Sales.discount, 0) + func.coalesce(Sales.fee, 0))), 0).label('total_sales_amount_cents'),
                func.coalesce(func.sum(case(
                    (Sales.liquidado == True, (func.coalesce(Sales.price, 0) - func.coalesce(Sales.discount, 0) + func.coalesce(Sales.fee, 0))),
                    else_=0
                )), 0).label('total_liquidated_amount_cents'),
            )
            .select_from(Sales)
            .outerjoin(Ticket, Ticket.sale_id == Sales.sale_id)
            .join(EventUserAccess, Sales.event == EventUserAccess.event_id)
            .filter(
                Sales.status == 'pagado',
                Sales.event == event_id,
                EventUserAccess.user_id == user_id,
            )
        )

        agg = sums_query.one_or_none()  # devuelve una tupla nombrada o None
        if agg is None:
            return jsonify({'message': 'No se encontraron datos para las agregaciones', 'status': 'error'}), 404

        total_tickets_sold = int(agg.total_tickets_sold or 0)
        total_tickets_liquidated = int(agg.total_tickets_liquidated or 0)
        total_sales_amount = float((agg.total_sales_amount_cents or 0) / 100.0)
        total_liquidated_amount = float((agg.total_liquidated_amount_cents or 0) / 100.0)

        # --- Consultas detalladas (ventas y liquidaciones) ---
        # Si quieres evitar cargar detalles cuando solo necesitas totales, podrías saltarte esta parte.
        query = (
            Sales.query
            .join(EventUserAccess, Sales.event == EventUserAccess.event_id)
            .options(
                joinedload(Sales.customer).load_only(EventsUsers.Email),
                joinedload(Sales.tickets).joinedload(Ticket.seat).joinedload(Seat.section),
                joinedload(Sales.payment).load_only(Payments.PaymentMethod),
                joinedload(Sales.event_rel).load_only(
                    Event.name, Event.event_id, Event.date_string, Event.hour_string,
                    Event.venue_id, Event.liquidado, Event.total_sales, Event.gross_sales,
                    Event.total_fees, Event.event_provider
                ).joinedload(Event.provider).load_only(Providers.ProviderID, Providers.ProviderName),
                load_only(
                    Sales.sale_id, Sales.price, Sales.discount, Sales.fee,
                    Sales.saleLink, Sales.creation_date, Sales.liquidado, Sales.liquidation_id
                ),
                joinedload(Sales.liquidation).load_only(
                    Liquidations.LiquidationID, Liquidations.LiquidationDate,
                    Liquidations.Amount, Liquidations.AmountBS, Liquidations.PaymentMethod,
                    Liquidations.Reference, Liquidations.Discount, Liquidations.AdditionalFees,
                    Liquidations.Comments
                )
            )
            .filter(
                Sales.status == 'pagado',
                Sales.event == event_id,
                EventUserAccess.user_id == user_id,
            )
        )

        sales = query.all()

        # Construir listas como antes (ventas no liquidadas y liquidaciones agrupadas)
        sales_data = []
        liquidations_map = {}
        for sale in sales:
            sale_tickets = sale.tickets or []
            if not sale.liquidado:
                sales_data.append({
                    'sale_id': getattr(sale, 'sale_id', None),
                    'price': round(((sale.price or 0) - (sale.discount or 0) + (sale.fee or 0)) / 100, 2),
                    'saleLink': getattr(sale, 'saleLink', ''),
                    'saleDate': sale.creation_date.isoformat() if getattr(sale, 'creation_date', None) else '',
                    'liquidado': bool(sale.liquidado),
                    'tickets': [
                        {
                            'ticket_id': getattr(ticket, 'ticket_id', None),
                            'sale_id': getattr(sale, 'sale_id', None),
                            'price': round((getattr(ticket, 'price', 0) or 0) / 100, 2),
                            'section': ticket.seat.section.name if (ticket.seat and getattr(ticket.seat, 'section', None)) else '',
                            'row': ticket.seat.row if ticket.seat else '',
                            'number': ticket.seat.number if ticket.seat else '',
                            'dateofPurchase': ticket.emission_date.isoformat() if getattr(ticket, 'emission_date', None) else ''
                        }
                        for ticket in sale_tickets
                    ],
                    'paymentsMethod': sale.payment.PaymentMethod if getattr(sale, 'payment', None) else ''
                })
            else:
                liq = getattr(sale, 'liquidation', None)
                if not liq:
                    continue
                lid = getattr(liq, 'LiquidationID', None) or getattr(liq, 'liquidation_id', None)
                if lid not in liquidations_map:
                    discounts_list = []
                    if getattr(liq, 'Discount', None):
                        for item in liq.Discount.split('||'):
                            try:
                                name, price = item.split(',', 1)
                                discounts_list.append({'name': name, 'price': int(price)})
                            except Exception:
                                continue

                    additional_fees_list = []
                    if getattr(liq, 'AdditionalFees', None):
                        for item in liq.AdditionalFees.split('||'):
                            try:
                                name, price = item.split(',', 1)
                                additional_fees_list.append({'name': name, 'price': int(price)})
                            except Exception:
                                continue

                    liquidations_map[lid] = {
                        'liquidation_id': lid,
                        'event_id': getattr(liq, 'EventID', event_id),
                        'amount_usd': round((getattr(liq, 'Amount', 0) or 0) / 100, 2),
                        'amount_bsd': round((getattr(liq, 'AmountBS', 0) or 0) / 100, 2),
                        'liquidation_date': liq.LiquidationDate.isoformat() if getattr(liq, 'LiquidationDate', None) else '',
                        'created_by': getattr(liq, 'CreatedBy', ''),
                        'comments': getattr(liq, 'Comments', ''),
                        'payment_method': getattr(liq, 'PaymentMethod', ''),
                        'reference': getattr(liq, 'Reference', ''),
                        'discounts': discounts_list,
                        'additional_charges': additional_fees_list,
                        'tickets': []
                    }

                for ticket in sale_tickets:
                    liquidations_map[lid]['tickets'].append({
                        'ticket_id': getattr(ticket, 'ticket_id', None),
                        'sale_id': getattr(sale, 'sale_id', None),
                        'price': round((getattr(ticket, 'price', 0) or 0) / 100, 2),
                        'section': ticket.seat.section.name if (ticket.seat and getattr(ticket.seat, 'section', None)) else '',
                        'row': ticket.seat.row if ticket.seat else '',
                        'number': ticket.seat.number if ticket.seat else '',
                        'dateofPurchase': ticket.emission_date.isoformat() if getattr(ticket, 'emission_date', None) else ''
                    })

        liquidations_data = sorted(liquidations_map.values(), key=lambda x: x.get('liquidation_date', ''), reverse=True)
        sales_data = sorted(sales_data, key=lambda x: x.get('saleDate', ''), reverse=True)

        # Información del evento (metadata)
        event_obj = Event.query.options(
            load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string, Event.venue_id, Event.liquidado, Event.total_sales, Event.gross_sales, Event.total_fees, Event.event_provider),
            joinedload(Event.provider).load_only(Providers.ProviderID, Providers.ProviderName),
            joinedload(Event.venue).load_only(Venue.venue_id, Venue.name)
        ).filter(Event.event_id == event_id).one_or_none()

        if not event_obj:
            return jsonify({'message': 'Evento no encontrado', 'status': 'error'}), 404

        event_info = {
            "event_id": event_obj.event_id,
            "provider_name": event_obj.provider.ProviderName if getattr(event_obj, 'provider', None) else '',
            "event": event_obj.name,
            "event_date": event_obj.date_string,
            "event_hour": event_obj.hour_string,
            "event_place": event_obj.venue.name if getattr(event_obj, 'venue', None) else '',
            "total_liquidated": total_liquidated_amount,
            "total_sales": total_sales_amount,
            "gross_sales": round(((getattr(event_obj, 'gross_sales', 0) or 0) / 100), 2),
            "total_tickets_sold": total_tickets_sold,
            "total_tickets_liquidated": total_tickets_liquidated
        }

        return jsonify({"sales": sales_data, "liquidations": liquidations_data, "status": "ok", "event": event_info}), 200
    except Exception:
        if db.session.is_active:
            db.session.rollback()
        logging.exception("Error en load_liquidations (aggregations)")
        return jsonify({'message': 'Error interno', 'status': 'error'}), 500

    finally:
        db.session.close()