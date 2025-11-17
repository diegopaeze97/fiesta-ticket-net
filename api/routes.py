from flask import request, jsonify, Blueprint, make_response, session, current_app, g
from flask_jwt_extended import create_access_token,  set_access_cookies, jwt_required, verify_jwt_in_request
from werkzeug.security import  check_password_hash, generate_password_hash
from extensions import db, s3, stripe
from models import EventsUsers, Revoked_tokens, Event, Venue, Section, Seat, Ticket, Financiamientos, Sales, Logs, Payments, Active_tokens, VerificationCode, VerificationAttempt
from flask_jwt_extended import get_jwt, get_jti
from flask_mail import Message
import logging
from sqlalchemy.orm import joinedload, load_only
from sqlalchemy import and_, or_, func, not_
import os
import bleach
import pandas as pd
from datetime import datetime, timedelta, timezone
import eventos.utils as utils
import eventos.utils_whatsapp as WA_utils
from extensions import mail
from decorators.utils import optional_roles, roles_required
import signup.utils as signup_utils
import requests
import re
import calendar
from dateutil import parser
import time
from models import Event
from requests.adapters import HTTPAdapter, Retry
from decimal import Decimal, InvalidOperation

api = Blueprint('api', __name__)

@api.route("/get-tickets", methods=["GET"])  # obtiene los tickets de un usuario
@roles_required(allowed_roles=["admin", "customer", "tiquetero", "provider", "super_admin"])
def get_tickets():
    # obtener user id desde el JWT
    try:
        user_id = int(get_jwt().get("id"))
    except Exception:
        return jsonify({"message": "User ID not found in token", "status": "error", "redirect": "/login"}), 400

    raw_status = (request.args.get("status") or "").strip().lower()
    today_str = datetime.now().strftime("%Y-%m-%d")

    # opciones de carga eager para evitar N+1
    base_options = [
        load_only(
            Ticket.ticket_id,
            Ticket.availability_status,
            Ticket.price,
            Ticket.saleLink,
            Ticket.emission_date,
            Ticket.customer_id,
            Ticket.event_id,
            Ticket.seat_id,
            Ticket.sale_id,
        ),
        joinedload(Ticket.seat).
            load_only(Seat.row, Seat.number, Seat.section_id).
            joinedload(Seat.section).
            load_only(Section.name),
        joinedload(Ticket.event).
            load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string, Event.venue_id).
            joinedload(Event.venue).
            load_only(Venue.name)
    ]

    # base query: tickets del usuario con eager loading
    query = Ticket.query.options(*base_options).join(Event).filter(Ticket.customer_id == user_id)

    # filtrar en la DB según el parámetro status para reducir filas transferidas
    if raw_status == "listo para canjear":
        # tickets marcados como "Listo para canjear" y con fecha del evento >= hoy
        query = query.filter(
            and_(
                Ticket.availability_status == "Listo para canjear",
                Event.date_string >= today_str
            )
        )
    elif raw_status == "canjeado":
        # tickets ya canjeados o eventos con fecha pasada
        query = query.filter(
            or_(
                Ticket.availability_status == "canjeado",
                Event.date_string < today_str
            )
        )
    else:
        # comportamiento por defecto: cargar ambos estados
        query = query.filter(Ticket.availability_status.in_(["canjeado", "Listo para canjear"]))

    tickets = query.all()

    if not tickets:
        return jsonify({"message": "No tickets found for this user", "status": "error", "tickets": []}), 200

    tickets_data = []
    for ticket in tickets:
        # convertir price de forma segura
        try:
            price = float(ticket.price) / 100.0 if ticket.price is not None else None
        except Exception:
            price = None

        event = getattr(ticket, "event", None)
        seat = getattr(ticket, "seat", None)

        website = current_app.config.get('WEBSITE_FRONTEND_TICKERA', '')

        ticket_info = {
            "id": ticket.ticket_id,
            "status": raw_status,
            "price": price,
            "qrData": f'{website}/tickets?query={ticket.saleLink}',
            "event": {
                "event_id": getattr(event, "event_id", None),
                "name": getattr(event, "name", None),
                "date": f'{getattr(event, "date_string", None)}T12:00:00' if getattr(event, "date_string", None) else None,
                "hour": getattr(event, "hour_string", None),
                "venue": event.venue.name if (event and getattr(event, "venue", None)) else None
            },
            "seat": {
                "section": seat.section.name if (seat and getattr(seat, "section", None)) else None,
                "row": seat.row if seat else None,
                "number": seat.number if seat else None
            },
            "emission_date": ticket.emission_date.isoformat() if getattr(ticket, "emission_date", None) else None
        }
        tickets_data.append(ticket_info)

    #return jsonify({"tickets": tickets_data, "status": "ok"}), 200
    return jsonify({"tickets": [], "status": "ok"}), 200

