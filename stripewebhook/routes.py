from flask import jsonify, Blueprint, render_template, request, current_app
from flask import render_template, request, redirect, url_for
from flask_jwt_extended import verify_jwt_in_request, get_jwt, jwt_required
from extensions import stripe, db
import os
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import or_
import datetime
import stripewebhook.utils as stripe_utils
import logging

stripewebhook = Blueprint('stripewebhook', __name__)

@stripewebhook.route("/paymentwebhook", methods=["POST"])
def payment_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")
    if not sig_header:
        logging.error("No Stripe-Signature header found")
        return jsonify({"error": "Missing Stripe-Signature header"}), 400
    event = None

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET_KEY'))
    except Exception as e:
        logging.error(f"Signature Verification Error: {e}")
        return jsonify({"error": str(e)}), 400

    try:
        event_type = event["type"]
        data_object = event["data"]["object"]
        logging.info(f"Received event: {event_type}")

        if event_type == "checkout.session.completed":
            stripe_utils.handle_checkout_completed(data_object, current_app.config)

        return jsonify(success=True), 200

    except Exception as e:
        logging(f"⚠️ Error procesando evento {event_type}: {e}")
        return jsonify(success=False), 500