"""
Meta Conversions API (CAPI) integration.

Sends server-side events to Meta to track:
- AddToCart: when a user adds tickets to the cart (/buy-tickets)
- InitiateCheckout: when a user initiates payment (/block-tickets, /create-stripe-checkout-session)
- Purchase: when a payment is confirmed (/validate-c2p, Stripe webhook, PagoMóvil auto-verification)

All PII is hashed with SHA-256 before transmission, as required by Meta.
"""

import hashlib
import logging
import time
import requests

META_CAPI_URL = "https://graph.facebook.com/v19.0/{pixel_id}/events"


def _sha256(value: str) -> str:
    """Return lowercase-stripped SHA-256 hex digest of a string."""
    if not value:
        return None
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _build_user_data(customer, client_ip: str = None, client_user_agent: str = None) -> dict:
    """
    Build the user_data payload from a customer (EventsUsers) object.
    All identifiable fields are hashed as required by Meta CAPI.
    """
    user_data = {}

    if customer.Email:
        user_data["em"] = [_sha256(customer.Email)]

    phone_raw = None
    if customer.CountryCode and customer.PhoneNumber:
        phone_raw = f"{customer.CountryCode}{customer.PhoneNumber}".replace("+", "").replace(" ", "").replace("-", "")
    elif customer.PhoneNumber:
        phone_raw = customer.PhoneNumber.replace("+", "").replace(" ", "").replace("-", "")

    if phone_raw:
        user_data["ph"] = [_sha256(phone_raw)]

    if customer.FirstName:
        user_data["fn"] = [_sha256(customer.FirstName)]

    if customer.LastName:
        user_data["ln"] = [_sha256(customer.LastName)]

    if client_ip:
        user_data["client_ip_address"] = client_ip

    if client_user_agent:
        user_data["client_user_agent"] = client_user_agent

    return user_data


def _send_event(pixel_id: str, access_token: str, event_name: str,
                user_data: dict, custom_data: dict,
                event_id: str = None) -> None:
    """
    Fire-and-forget POST to Meta CAPI.
    Logs errors but never raises, so a tracking failure never breaks the main flow.
    """
    if not pixel_id or not access_token:
        logging.warning("Meta CAPI: pixel_id or access_token not configured, skipping event '%s'", event_name)
        return

    payload = {
        "data": [
            {
                "event_name": event_name,
                "event_time": int(time.time()),
                "action_source": "website",
                "user_data": user_data,
                "custom_data": custom_data,
            }
        ]
    }

    if event_id:
        payload["data"][0]["event_id"] = event_id

    url = META_CAPI_URL.format(pixel_id=pixel_id)

    try:
        response = requests.post(
            url,
            params={"access_token": access_token},
            json=payload,
            timeout=10,
        )
        if response.status_code != 200:
            logging.warning(
                "Meta CAPI returned non-200 for event '%s': %s %s",
                event_name, response.status_code, response.text
            )
        else:
            logging.info("Meta CAPI event '%s' sent successfully", event_name)
    except Exception:
        logging.exception("Meta CAPI: failed to send event '%s'", event_name)


# ---------------------------------------------------------------------------
# Public helpers – one function per business event
# ---------------------------------------------------------------------------

def track_add_to_cart(config: dict, customer, tickets: list,
                      amount_usd: float, event_name: str,
                      client_ip: str = None, client_user_agent: str = None) -> None:
    """
    Track an AddToCart event.

    :param config: Flask app.config dict
    :param customer: EventsUsers ORM instance
    :param tickets: list of Ticket ORM instances added to cart
    :param amount_usd: total value in USD (already divided by 100)
    :param event_name: name of the event/show (Event.name)
    :param client_ip: client IP address from the request
    :param client_user_agent: User-Agent header from the request
    """
    pixel_id = config.get("META_PIXEL_ID")
    access_token = config.get("META_ACCESS_TOKEN")

    user_data = _build_user_data(customer, client_ip, client_user_agent)

    content_ids = [str(t.ticket_id) for t in tickets]

    custom_data = {
        "value": round(amount_usd, 2),
        "currency": "USD",
        "content_ids": content_ids,
        "content_type": "product",
        "content_name": event_name,
        "num_items": len(tickets),
    }

    _send_event(pixel_id, access_token, "AddToCart", user_data, custom_data)


def track_initiate_checkout(config: dict, customer, tickets: list,
                            amount_usd: float, event_name: str,
                            payment_method: str = None,
                            client_ip: str = None, client_user_agent: str = None) -> None:
    """
    Track an InitiateCheckout event (user submits a payment request).

    :param payment_method: e.g. 'pagomovil', 'stripe', 'c2p', 'efectivo', etc.
    """
    pixel_id = config.get("META_PIXEL_ID")
    access_token = config.get("META_ACCESS_TOKEN")

    user_data = _build_user_data(customer, client_ip, client_user_agent)

    content_ids = [str(t.ticket_id) for t in tickets]

    custom_data = {
        "value": round(amount_usd, 2),
        "currency": "USD",
        "content_ids": content_ids,
        "content_type": "product",
        "content_name": event_name,
        "num_items": len(tickets),
    }

    if payment_method:
        custom_data["payment_method"] = payment_method

    _send_event(pixel_id, access_token, "InitiateCheckout", user_data, custom_data)


def track_purchase(config: dict, customer, tickets: list,
                   amount_usd: float, event_name: str,
                   payment_method: str = None, order_id: str = None,
                   client_ip: str = None, client_user_agent: str = None) -> None:
    """
    Track a Purchase event (payment confirmed).

    :param order_id: sale locator or Stripe session ID used as dedup event_id
    """
    pixel_id = config.get("META_PIXEL_ID")
    access_token = config.get("META_ACCESS_TOKEN")

    user_data = _build_user_data(customer, client_ip, client_user_agent)

    content_ids = [str(t.ticket_id) for t in tickets]

    custom_data = {
        "value": round(amount_usd, 2),
        "currency": "USD",
        "content_ids": content_ids,
        "content_type": "product",
        "content_name": event_name,
        "num_items": len(tickets),
    }

    if payment_method:
        custom_data["payment_method"] = payment_method

    _send_event(pixel_id, access_token, "Purchase", user_data, custom_data, event_id=order_id)
