from flask import request, jsonify, Blueprint, current_app
from extensions import db, s3
from flask_jwt_extended import get_jwt
import logging
from sqlalchemy.orm import joinedload, load_only
from sqlalchemy import func
from models import Sales, Ticket, Seat, Event, SellerCommissions, EventsUsers, SellerCommissionPayments
from decorators.utils import roles_required
from datetime import datetime, timezone
import sellers.utils as seller_utils

sellers = Blueprint('sellers', __name__)

@sellers.route("/get-tickets", methods=["GET"])  # obtiene los tickets de un usuario
@roles_required(allowed_roles=["admin", "customer", "seller", "tiquetero", "provider", "super_admin"])
def get_tickets():
    user_role = get_jwt().get("role")
    user_id = get_jwt().get("id")
    try:
        if user_role == "seller":
            # Tickets relacionados a ventas creadas por este vendedor
            sales = Sales.query.options(
                joinedload(Sales.tickets).joinedload(Ticket.seat).joinedload(Seat.section),
                joinedload(Sales.event_rel).load_only(Event.event_id, Event.name)
            ).filter(Sales.created_by == int(user_id)).all()
            tickets = []
            for sale in sales:
                for t in sale.tickets:
                    tickets.append({
                        "ticket_id": t.ticket_id,
                        "sale_id": sale.sale_id,
                        "section": t.seat.section.name if (t.seat and t.seat.section) else "",
                        "row": t.seat.row if t.seat else "",
                        "number": t.seat.number if t.seat else "",
                        "price": round((t.price or 0)/100, 2),
                        "status": t.status,
                        "event": sale.event_rel.name if sale.event_rel else ""
                    })
            return jsonify({"tickets": tickets, "status": "ok"}), 200

        # admin / other roles: devolver todos (limitado)
        tickets_q = Ticket.query.options(
            joinedload(Ticket.seat).joinedload(Seat.section),
            joinedload(Ticket.event).load_only(Event.event_id, Event.name)
        ).limit(1000).all()
        tickets = [{
            "ticket_id": t.ticket_id,
            "sale_id": t.sale_id,
            "section": t.seat.section.name if (t.seat and t.seat.section) else "",
            "row": t.seat.row if t.seat else "",
            "number": t.seat.number if t.seat else "",
            "price": round((t.price or 0)/100, 2),
            "status": t.status,
            "event": t.event.name if t.event else ""
        } for t in tickets_q]
        return jsonify({"tickets": tickets, "status": "ok"}), 200
    except Exception as e:
        logging.exception(f"Error obteniendo tickets: {e}")
        return jsonify({"message": "Error interno", "status": "error"}), 500

# Nuevo endpoint para dashboard del vendedor
@sellers.route("/dashboard", methods=["GET"])
@roles_required(allowed_roles=["seller", "admin", "super_admin"])
def seller_dashboard():
    user_role = get_jwt().get("role")
    user_id = get_jwt().get("id")
    try:
        # Solo vendedores (o admin) pueden ver su dashboard. Si admin, puede pasar sellerId en query
        seller_id = request.args.get("sellerId")
        if user_role == "admin" and seller_id and str(seller_id).isdigit():
            seller_id = int(seller_id)
        else:
            seller_id = int(user_id)

        # Cargar ventas creadas por este vendedor
        sales_q = Sales.query.options(
            joinedload(Sales.tickets).joinedload(Ticket.seat).joinedload(Seat.section),
            joinedload(Sales.payment),
            joinedload(Sales.event_rel).load_only(Event.event_id, Event.name, Event.date_string, Event.hour_string),
            joinedload(Sales.customer).load_only(EventsUsers.CustomerID, EventsUsers.FirstName, EventsUsers.LastName, EventsUsers.Email),
            load_only(Sales.sale_id, Sales.price, Sales.discount, Sales.fee, Sales.creation_date)
        ).filter(Sales.created_by == seller_id).order_by(Sales.creation_date.desc())

        sales = sales_q.all()

        sales_payload = []
        total_tickets = 0
        total_revenue_cents = 0

        # preload commissions for these sales
        sale_ids = [s.sale_id for s in sales]
        commissions_map = {}
        if sale_ids:
            commissions = SellerCommissions.query.filter(
                SellerCommissions.SaleID.in_(sale_ids),
                SellerCommissions.SellerID == seller_id
            ).all()
            for c in commissions:
                commissions_map.setdefault(c.SaleID, 0)
                commissions_map[c.SaleID] += (c.CommissionAmount or 0)

        for s in sales:
            tickets_list = []
            for t in s.tickets:
                tickets_list.append({
                    "section": t.seat.section.name.replace('20_', ' ') if (t.seat and t.seat.section and t.seat.section.name) else "",
                    "ticket_id": str(t.ticket_id),
                    "sale_id": str(s.sale_id),
                    "price": round((t.price or 0)/100, 2),
                    "row": t.seat.row if t.seat else "",
                    "number": t.seat.number if t.seat else "",
                    "EmissionDate": t.emission_date.isoformat() if t.emission_date else None
                })
                total_tickets += 1
            # revenue for sale = price - discount + fee (stored in cents)
            sale_revenue_cents = int((s.price or 0) - (s.discount or 0) + (s.fee or 0))
            total_revenue_cents += sale_revenue_cents

            sale_comm_cents = commissions_map.get(s.sale_id, 0)
            sale_payload = {
                "sale_id": s.sale_id,
                "price": round(sale_revenue_cents/100, 2),
                "saleDate": s.creation_date.isoformat() if getattr(s, "creation_date", None) else None,
                "tickets": tickets_list,
                "paymentsMethod": s.payment.PaymentMethod if s.payment else None,
                "commission": round(sale_comm_cents/100, 2)
            }
            sales_payload.append(sale_payload)

        # total commissions
        total_commissions_cents = db.session.query(func.coalesce(func.sum(SellerCommissions.CommissionAmount), 0)).filter(SellerCommissions.SellerID == seller_id).scalar() or 0

        stats = {
            "total_sales": len(sales_payload),
            "total_revenue": round(total_revenue_cents/100, 2),
            "total_commission": round(total_commissions_cents/100, 2),
            "total_tickets_sold": total_tickets
        }

        # all_tickets as flattened list (useful for charts)
        all_tickets = []
        for sp in sales_payload:
            for t in sp["tickets"]:
                all_tickets.append(t)

        return jsonify({
            "sales": sales_payload,
            "all_tickets": all_tickets,
            "stats": stats,
            "status": "ok"
        }), 200

    except Exception as e:
        logging.exception(f"Error cargando dashboard vendedor: {e}")
        return jsonify({"message": "Error interno", "status": "error"}), 500

# Endpoint para obtener vendedores + estadísticas (consumido por frontend)
@sellers.route("/liquidations", methods=["GET"])
@roles_required(allowed_roles=["admin", "super_admin"])
def admin_sellers_liquidations():
    try:
        seller_roles = ["seller"]
        sellers_q = EventsUsers.query.filter(EventsUsers.role.in_(seller_roles)).all()

        sellers_payload = []
        for seller in sellers_q:
            # ventas creadas por este vendedor
            sales_q = Sales.query.options(
                joinedload(Sales.tickets).joinedload(Ticket.seat).joinedload(Seat.section),
                joinedload(Sales.payment),
                joinedload(Sales.event_rel).load_only(Event.event_id, Event.name),
                load_only(Sales.sale_id, Sales.price, Sales.discount, Sales.fee, Sales.creation_date, Sales.liquidado)
            ).filter(Sales.created_by == seller.CustomerID, Sales.seller_commission == True).order_by(Sales.creation_date.desc()).all()

            sales_payload = []
            total_tickets = 0
            total_revenue_cents = 0

            # preload commissions for these sales for this seller
            sale_ids = [s.sale_id for s in sales_q]
            commissions_map = {}
            if sale_ids:
                commissions = SellerCommissions.query.filter(
                    SellerCommissions.SaleID.in_(sale_ids),
                    SellerCommissions.SellerID == seller.CustomerID
                ).all()
                for c in commissions:
                    commissions_map.setdefault(c.SaleID, [])
                    commissions_map[c.SaleID].append(c)

            for s in sales_q:
                tickets_list = []
                for t in s.tickets:
                    tickets_list.append({
                        "section": t.seat.section.name.replace('20_', ' ') if (t.seat and t.seat.section and t.seat.section.name) else "",
                        "ticket_id": str(t.ticket_id),
                        "sale_id": str(s.sale_id),
                        "price": round((t.price or 0)/100, 2),
                        "row": t.seat.row if t.seat else "",
                        "number": t.seat.number if t.seat else "",
                        "EmissionDate": t.emission_date.isoformat() if t.emission_date else None
                    })
                    total_tickets += 1

                sale_revenue_cents = int((s.price or 0) - (s.discount or 0) + (s.fee or 0))
                total_revenue_cents += sale_revenue_cents

                # comisión específica para este vendedor y venta (suma si hay varios registros)
                sale_comm_cents = 0
                paid_out = False
                for c in commissions_map.get(s.sale_id, []):
                    sale_comm_cents += (c.CommissionAmount or 0)
                    if c.PaidOut:
                        paid_out = True

                sale_payload = {
                    "sale_id": s.sale_id,
                    "price": round(sale_revenue_cents/100, 2),
                    "saleDate": s.creation_date.isoformat() if getattr(s, "creation_date", None) else None,
                    "tickets": tickets_list,
                    "paymentsMethod": s.payment.PaymentMethod if s.payment else None,
                    "commission": round(sale_comm_cents/100, 2),
                    "liquidated": paid_out or bool(getattr(s, "liquidado", False))
                }
                sales_payload.append(sale_payload)

            total_commissions_cents = db.session.query(
                func.coalesce(func.sum(SellerCommissions.CommissionAmount), 0)
            ).filter(SellerCommissions.SellerID == seller.CustomerID).scalar() or 0

            stats = {
                "total_sales": len(sales_payload),
                "total_revenue": round(total_revenue_cents/100, 2),
                "total_commission": round(total_commissions_cents/100, 2),
                "total_tickets_sold": total_tickets
            }

            sellers_payload.append({
                "seller_id": str(seller.CustomerID),
                "seller_name": f"{(seller.FirstName or '').strip()} {(seller.LastName or '').strip()}".strip() or "Sin nombre",
                "seller_email": seller.Email or "",
                "stats": stats,
                "sales": sales_payload
            })

        return jsonify({"sellers": sellers_payload, "status": "ok"}), 200
    except Exception as e:
        logging.exception(f"Error obteniendo liquidaciones de vendedores: {e}")
        return jsonify({"message": "Error interno", "status": "error"}), 500

# Endpoint para procesar liquidación (marca comisiones como pagadas)
@sellers.route("/liquidate", methods=["POST"])
@roles_required(allowed_roles=["admin", "super_admin"])
def admin_sellers_liquidate():
    try:
        payload = request.get_json() or {}
        seller_id = payload.get("seller_id")
        sale_ids = payload.get("sale_ids", [])
        payment = payload.get("payment", {})
        totals = payload.get("totals", {}) or {}
        additional_charges = payload.get("additionalCharges", []) or []
        discounts = payload.get("discounts", []) or []
        comments = payload.get("comments", "")

        if not seller_id or not sale_ids:
            return jsonify({"message": "seller_id y sale_ids son requeridos", "status": "error"}), 400

        # normalizar sale ids a ints
        sale_ids_int = []
        for sid in sale_ids:
            try:
                sale_ids_int.append(int(sid))
            except Exception:
                continue

        if not sale_ids_int:
            return jsonify({"message": "sale_ids inválidos", "status": "error"}), 400

        # Totales provenientes del frontend vienen en unidades (ej: USD), convertir a "cents"/enteros
        def to_cents(value):
            try:
                return int(round((value or 0) * 100))
            except Exception:
                return 0

        total_commission_cents = to_cents(totals.get("totalCommission"))
        total_charges_cents = to_cents(totals.get("totalCharges"))
        total_discounts_cents = to_cents(totals.get("totalDiscounts"))
        final_amount_cents = to_cents(totals.get("finalAmount"))

        # Serializar cargos y descuentos como "name:amount||name2:amount" (amount en cents)
        def serialize_charges(charges):
            parts = []
            for c in charges:
                name = (c.get("name") or "").strip()
                amount_c = to_cents(c.get("price") or c.get("amount"))
                parts.append(f"{name}:{amount_c}")
            return "||".join(parts)

        additional_charges_str = serialize_charges(additional_charges)
        discounts_str = serialize_charges(discounts)

        # Parsear fecha de pago si viene, si no usar ahora
        payment_date = None
        if payment and payment.get("date"):
            try:
                payment_date = datetime.fromisoformat(payment.get("date"))
            except Exception:
                payment_date = datetime.now(timezone.utc)
        else:
            payment_date = datetime.now(timezone.utc)

        # Crear registro de pago en seller_commission_payments
        try:
            amount_bs = None
            if payment.get("currency") == "bolivares" and payment.get("amountBolivares") is not None:
                # almacenar en "centavos" de la misma forma (multiplicar por 100)
                amount_bs = to_cents(payment.get("amountBolivares"))

            created_by = None
            approved_by = None
            jwt = get_jwt() or {}
            try:
                created_by = int(jwt.get("id")) if jwt.get("id") else None
                approved_by = created_by
            except Exception:
                created_by = None
                approved_by = None

            new_payment = SellerCommissionPayments(
                SellerID=int(seller_id),
                PaymentMethod=payment.get("method") or payment.get("paymentMethod") or "",
                Reference=payment.get("reference") or payment.get("ref") or "",
                PaymentDate=payment_date,
                Currency=payment.get("currency") or "USD",
                AmountBS=amount_bs,
                AddiitionalCharges=additional_charges_str,
                Discounts=discounts_str,
                Comments=comments,
                TotalComission=total_commission_cents,
                TotalCharges=total_charges_cents,
                TotalDiscounts=total_discounts_cents,
                FinalAmount=final_amount_cents,
                ApprovedBy=approved_by,
                CreatedBy=created_by
            )

            db.session.add(new_payment)
            db.session.flush()  # para obtener PaymentID antes del commit
        except Exception as e:
            logging.exception(f"Error creando registro de pago de comisiones: {e}")
            return jsonify({"message": "Error creando registro de pago", "status": "error"}), 500

        # Buscar comisiones correspondientes y marcarlas como pagadas, enlazarlas al pago creado
        commissions = SellerCommissions.query.filter(
            SellerCommissions.SaleID.in_(sale_ids_int),
            SellerCommissions.SellerID == int(seller_id)
        ).all()

        updated = 0
        for c in commissions:
            c.PaidOut = True
            c.PaymentDate = payment_date
            # enlazar con el pago creado
            try:
                c.PaymentID = new_payment.PaymentID
            except Exception:
                # si la columna en la tabla se llama diferente, intentar asignar linked_payment
                try:
                    c.linked_payment = new_payment
                except Exception:
                    pass
            updated += 1

        # Commit DB antes de generar PDF (necesitamos el PaymentID)
        db.session.commit()

        # -------------------------
        # Obtener información del vendedor y ventas para el PDF
        # -------------------------
        seller = EventsUsers.query.filter_by(CustomerID=int(seller_id)).first()
        if not seller:
            logging.error(f"No se encontró el vendedor con ID {seller_id}")
            return jsonify({
                "status": "ok",
                "updated": updated,
                "payment_id": new_payment.PaymentID,
                "warning": "Liquidación creada pero no se pudo generar PDF (vendedor no encontrado)"
            }), 200

        # Obtener ventas con información completa para el PDF
        sales = Sales.query.options(
            joinedload(Sales.tickets),
            joinedload(Sales.event_rel).load_only(Event.event_id, Event.name)
        ).filter(Sales.sale_id.in_(sale_ids_int)).all()

        # Preparar datos de ventas para el PDF
        sales_data = []
        for sale in sales:
            # Calcular comisión total para esta venta
            sale_commission = sum((c.CommissionAmount or 0) for c in commissions if c.SaleID == sale.sale_id)
            
            sales_data.append({
                "sale_id": sale.sale_id,
                "sale_date": sale.creation_date,
                "event_name": sale.event_rel.name if sale.event_rel else "N/A",
                "ticket_count": len(sale.tickets),
                "sale_amount": (sale.price or 0) - (sale.discount or 0) + (sale.fee or 0),
                "commission_amount": sale_commission
            })

        # Preparar datos de totales para el PDF
        totals_pdf = {
            "totalCommission": total_commission_cents / 100,
            "totalCharges": total_charges_cents / 100,
            "totalDiscounts": total_discounts_cents / 100,
            "finalAmount": final_amount_cents / 100
        }

        # Parsear cargos adicionales y descuentos para el PDF
        charges_list = []
        if additional_charges:
            for charge in additional_charges:
                charges_list.append({
                    "name": charge.get("name", ""),
                    "amount": charge.get("price", 0) or charge.get("amount", 0)
                })

        discounts_list = []
        if discounts:
            for discount in discounts:
                discounts_list.append({
                    "name": discount.get("name", ""),
                    "amount": discount.get("price", 0) or discount.get("amount", 0)
                })

        # -------------------------
        # Generar PDF en memoria
        # -------------------------
        pdf_bytes = None
        try:
            pdf_bytes = seller_utils.generate_seller_liquidation_pdf(
                payment=new_payment,
                seller=seller,
                sales_data=sales_data,
                totals=totals_pdf,
                additional_charges=charges_list,
                discounts=discounts_list,
                comments=comments
            )
        except Exception as e:
            logging.exception(f"Error generando PDF de liquidación del vendedor: {e}")
            # No retornamos error aquí, continuamos sin PDF

        # -------------------------
        # Subir PDF a S3 y guardar link
        # -------------------------
        if pdf_bytes:
            S3_BUCKET = "imagenes-fiestatravel"
            s3_key = f"seller_liquidations/{new_payment.PaymentID}.pdf"
            
            try:
                pdf_url = seller_utils.upload_pdf_to_s3_public(s3, S3_BUCKET, s3_key, pdf_bytes)
                if pdf_url:
                    # Guardar URL en la base de datos
                    new_payment.ReceiptLink = pdf_url
                    db.session.commit()
                    logging.info(f"PDF de liquidación guardado en S3: {pdf_url}")
                else:
                    logging.error("No se pudo subir el PDF a S3")
            except Exception as e:
                logging.exception(f"Error subiendo PDF a S3: {e}")

        # -------------------------
        # Enviar notificaciones por correo
        # -------------------------
        if pdf_bytes:
            try:
                # Notificar al vendedor
                seller_utils.send_seller_liquidation_notification(
                    config=current_app.config,
                    seller=seller,
                    payment=new_payment,
                    pdf_bytes=pdf_bytes,
                    totals=totals_pdf,
                    sale_count=len(sales_data)
                )
            except Exception as e:
                logging.exception(f"Error enviando notificación al vendedor: {e}")

            try:
                # Notificar a los administradores
                seller_utils.send_admin_liquidation_notification(
                    config=current_app.config,
                    seller=seller,
                    payment=new_payment,
                    pdf_bytes=pdf_bytes,
                    totals=totals_pdf,
                    sale_count=len(sales_data),
                    sale_ids=sale_ids_int
                )
            except Exception as e:
                logging.exception(f"Error enviando notificación a administradores: {e}")

        return jsonify({
            "status": "ok",
            "updated": updated,
            "payment_id": new_payment.PaymentID,
            "receipt_link": new_payment.ReceiptLink
        }), 200

    except Exception as e:
        logging.exception(f"Error procesando liquidación: {e}")
        return jsonify({"message": "Error interno", "status": "error"}), 500