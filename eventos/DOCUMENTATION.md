# Documentación del Módulo de Eventos

## Descripción General

El módulo `eventos` es la API principal que permite gestionar la venta, reserva y emisión de boletos para eventos. Este módulo proporciona endpoints para:

- Consulta de eventos y mapas de asientos
- Compra y reserva de boletos
- Procesamiento de pagos (Stripe, PagoMóvil, C2P, Débito Inmediato)
- Validación y canje de tickets
- Gestión de reservaciones

---

## Estructura de Archivos

```
eventos/
├── routes.py          # Definición de endpoints REST API
├── services.py        # Lógica de negocio y servicios
├── utils.py           # Funciones utilitarias y helpers
├── utils_whatsapp.py  # Integración con WhatsApp para notificaciones
└── DOCUMENTATION.md   # Este archivo
```

---

## Endpoints Disponibles

### 1. GET `/get-map`

**Descripción:** Obtiene el mapa SVG de asientos para un evento específico.

**Parámetros de Query:**
- `query` (string, requerido): ID del evento

**Respuesta Exitosa (200):**
```json
{
  "event": { ... },
  "sections": [ ... ],
  "svg_map": "<svg>...</svg>",
  "status": "ok"
}
```

**Autenticación:** No requerida

---

### 2. GET `/get-events`

**Descripción:** Lista todos los eventos activos disponibles.

**Respuesta Exitosa (200):**
```json
{
  "events": [
    {
      "event_id": 1,
      "name": "Nombre del Evento",
      "Description": "Descripción",
      "date": "2026-05-29",
      "hour": "09:00",
      "Venue": { ... },
      "mainImage": "url",
      "bannerImage": "url"
    }
  ],
  "status": "ok"
}
```

**Autenticación:** No requerida

---

### 3. POST `/buy-tickets`

**Descripción:** Agrega boletos al carrito del usuario.

**Roles Permitidos:** `admin`, `customer`, `seller`, `tiquetero`, `provider`, `super_admin`

**Parámetros de Query:**
- `query` (string, requerido): ID del evento

**Body (JSON):**
```json
{
  "tickets": [
    {
      "ticket_id": 123,
      "price": 5000
    }
  ],
  "discount_code": "DESCUENTO10"
}
```

**Validaciones:**
- Máximo 6 boletos por transacción
- Usuario debe estar verificado
- Evento debe estar activo
- Asientos deben estar disponibles

**Respuesta Exitosa (200):**
```json
{
  "message": "Tickets agregados al carrito exitosamente",
  "status": "ok",
  "tickets": [ ... ],
  "exchange_rate_bsd": 102.50
}
```

---

### 4. GET `/get-paymentdetails`

**Descripción:** Obtiene los detalles de pago para los tickets en el carrito.

**Roles Permitidos:** `admin`, `customer`, `seller`, `tiquetero`, `provider`, `super_admin`

**Parámetros de Query:**
- `query` (string, requerido): ID del evento
- `discount_code` (string, opcional): Código de descuento

**Respuesta Exitosa (200):**
```json
{
  "tickets": [ ... ],
  "total_price": 150.00,
  "total_fee": 22.50,
  "total_discount": 0,
  "event": { ... },
  "accepted_payment_methods": ["stripe", "pagomovil", "c2p"],
  "status": "ok"
}
```

---

### 5. POST `/block-tickets`

**Descripción:** Bloquea los tickets en el carrito y registra el pago inicial (reserva).

**Roles Permitidos:** `admin`, `customer`, `seller`, `tiquetero`, `provider`, `super_admin`

**Parámetros de Query:**
- `query` (string, requerido): ID del evento
- `discount_code` (string, opcional): Código de descuento

**Body (JSON):**
```json
{
  "paymentMethod": "pagomovil",
  "paymentReference": "123456789",
  "pagomovilPhoneNumber": "04121234567",
  "contactPhoneNumber": "04121234567",
  "countryCode": "+58",
  "bank": "BANESCO",
  "addons": []
}
```

**Métodos de Pago Soportados:**
- `pagomovil` - PagoMóvil venezolano
- `efectivo` - Pago en efectivo
- `zelle` - Transferencia Zelle
- `cashea` - Pago con Cashea

**Respuesta Exitosa (200):**
```json
{
  "message": "Tickets bloqueados y venta registrada exitosamente",
  "status": "pending",
  "tickets": [ ... ],
  "total": 172.50
}
```

---

### 6. GET `/reservation`

**Descripción:** Verifica si existe una reservación.

**Parámetros de Query:**
- `query` (string, requerido): ID de reservación (saleLink)

**Respuesta Exitosa (200):**
```json
{
  "message": "Reserva existente",
  "status": "ok"
}
```

**Autenticación:** No requerida

---

### 7. POST `/view-reservation`

**Descripción:** Obtiene los detalles completos de una reservación.

**Body (JSON):**
```json
{
  "input1": "A",
  "input2": "B",
  "input3": "C",
  "input4": "D",
  "input5": "E",
  "input6": "F",
  "reservation_id": "token_reserva"
}
```

> Los inputs 1-6 forman el código localizador de 6 caracteres.

**Respuesta Exitosa (200):**
```json
{
  "message": "Reserva encontrada",
  "status": "ok",
  "reservation_status": "active",
  "sale": { ... },
  "tickets": [ ... ],
  "payments": [ ... ]
}
```

---

### 8. GET `/ticket`

**Descripción:** Verifica la validez de un ticket.

**Roles Opcionales:** `admin`, `tiquetero` (para información adicional)

**Parámetros de Query:**
- `query` (string, requerido): Link del ticket (saleLink)

**Respuesta Exitosa (200):**
```json
{
  "message": "Ticket existente",
  "status": "ok",
  "ticket_status": "valid",
  "information": { ... }  // Solo si tiene rol permitido
}
```

---

### 9. POST `/view-ticket`

**Descripción:** Obtiene los detalles de un ticket usando el localizador.

**Body (JSON):**
```json
{
  "input1": "A",
  "input2": "B",
  "input3": "C",
  "input4": "D",
  "input5": "E",
  "input6": "F",
  "ticket_id": "token_ticket"
}
```

---

### 10. GET `/canjear-ticket`

**Descripción:** Canjea un ticket (marca como usado).

**Roles Permitidos:** `admin`, `tiquetero`

**Parámetros de Query:**
- `query` (string, requerido): ID del ticket

**Respuesta Exitosa (200):**
```json
{
  "message": "Ticket canjeado exitosamente",
  "status": "ok",
  "ticket_status": "used"
}
```

---

### 11. POST `/create-stripe-checkout-session`

**Descripción:** Crea una sesión de checkout de Stripe para procesar pagos con tarjeta.

**Roles Permitidos:** `admin`, `customer`, `seller`, `tiquetero`, `provider`, `super_admin`

**Parámetros de Query:**
- `query` (string, requerido): ID del evento
- `discount_code` (string, opcional): Código de descuento

**Body (JSON):**
```json
{
  "addons": []
}
```

**Respuesta Exitosa (200):**
```json
{
  "checkout_url": "https://checkout.stripe.com/...",
  "status": "ok"
}
```

---

### 12. POST `/get-debitoinmediato-code`

**Descripción:** Genera un código OTP para pagos con Débito Inmediato.

**Roles Permitidos:** `admin`, `customer`, `seller`, `tiquetero`, `provider`, `super_admin`

**Body (JSON):**
```json
{
  "event_id": "123",
  "paymentMethod": "debito inmediato",
  "cedula_type": "V",
  "cedula": "12345678",
  "telefono": "04121234567",
  "banco": "BANESCO",
  "carrito": [ ... ]
}
```

---

### 13. POST `/validate-c2p`

**Descripción:** Valida transacciones de PagoMóvil C2P en tiempo real.

**Roles Permitidos:** `admin`, `customer`, `seller`, `tiquetero`, `provider`, `super_admin`

**Body (JSON):**
```json
{
  "token": "OTP_TOKEN",
  "banco": "0102",
  "telefono": "04121234567",
  "cedula": "12345678",
  "nacionalidad": "V",
  "addons": []
}
```

**Parámetros de Query:**
- `query` (string, requerido): ID del evento
- `discount_code` (string, opcional): Código de descuento

---

## Servicios (services.py)

### `bvc_api_verification_success`

Procesa la verificación exitosa de un pago BVC API.

**Parámetros:**
- `config`: Configuración de la aplicación
- `tickets_en_carrito`: Lista de tickets en el carrito
- `payment`: Objeto de pago
- `customer`: Objeto del cliente
- `discount_code`: Código de descuento aplicado
- `validated_addons`: Complementos validados
- `total_price_addons`: Precio total de complementos

**Funcionalidad:**
1. Calcula descuentos proporcionales por ticket
2. Genera códigos QR para cada ticket
3. Actualiza estado de tickets a "pagado"
4. Envía notificaciones por email
5. Actualiza métricas del evento

---

### `preprocess_validation`

Valida y preprocesa los datos necesarios antes de procesar un pago.

**Parámetros:**
- `user_id`: ID del usuario
- `event_id`: ID del evento
- `addons`: Lista de complementos
- `discount_code`: Código de descuento
- `payment_method`: Método de pago

**Retorna:**
```python
{
    "customer": ...,
    "event": ...,
    "tickets": [...],
    "tickets_en_carrito": [...],
    "total_price": int,
    "total_price_tickets": int,
    "total_price_addons": int,
    "total_amount_to_pay": int,
    "total_fee": int,
    "total_discount": int,
    "validated_addons": [...],
    "discount_id": int
}
```

---

### `ticket_approval_c2p`

Procesa la aprobación de tickets pagados con C2P.

**Funcionalidad similar a `bvc_api_verification_success`.**

---

## Utilidades (utils.py)

### Funciones de Notificación

| Función | Descripción |
|---------|-------------|
| `sendqr_for_ConfirmedReservationOrFin` | Envía email con QR de reserva confirmada |
| `sendqr_for_SuccessfulTicketEmission` | Envía email con QR del boleto emitido |
| `sendqr_for_SuccessfulTicketsEmission` | Envía emails para múltiples tickets |
| `sendnotification_for_PaymentStatus` | Notifica estado del pago |
| `sendnotification_for_Blockage` | Notifica bloqueo de reserva |
| `sendnotification_for_CartAdding` | Notifica cuando se agrega al carrito |
| `sendnotification_for_CompletedPaymentStatus` | Notifica pago completado con factura |

### Funciones de Validación

| Función | Descripción |
|---------|-------------|
| `validate_discount_code` | Valida códigos de descuento |
| `get_exchange_rate_bsd` | Obtiene tasa de cambio USD/BsD |
| `get_accepted_payment_methods` | Obtiene métodos de pago aceptados por sección |
| `validate_addons` | Valida complementos adicionales |

### Funciones de Utilidad

| Función | Descripción |
|---------|-------------|
| `newQR` | Genera y sube QR a S3 |
| `update_user_gallery_newQR` | Actualiza QR en galería del usuario |
| `record_purchased_feature` | Registra características compradas |
| `clean_tickets` | Sanitiza lista de tickets |
| `accepts_all_payment_methods` | Verifica métodos de pago aceptados |

---

## Estándares y Prácticas

### 1. Validación de Datos

- **Sanitización:** Todos los inputs de texto se sanitizan con `bleach.clean()`
- **Validación de IDs:** Se valida que los IDs sean numéricos antes de convertirlos
- **Límites:** Máximo 6 boletos por transacción

### 2. Manejo de Errores

```python
try:
    # Lógica de negocio
except Exception as e:
    db.session.rollback()
    logging.error(f"Error: {str(e)}")
    return jsonify({"message": "Error descriptivo", "status": "error"}), 500
```

### 3. Transacciones de Base de Datos

- Usar `db.session.flush()` antes de crear entidades dependientes
- Usar `db.session.commit()` al final de operaciones exitosas
- Usar `db.session.rollback()` en caso de errores

### 4. Autenticación y Autorización

```python
@roles_required(allowed_roles=["admin", "customer", "seller", "tiquetero", "provider", "super_admin"])
def endpoint():
    user_id = get_jwt().get("id")
    # ...
```

### 5. Respuestas API

Formato estándar de respuesta:
```json
{
  "message": "Descripción del resultado",
  "status": "ok" | "error",
  "data": { ... }
}
```

Códigos HTTP utilizados:
- `200` - Operación exitosa
- `400` - Error de validación / datos inválidos
- `403` - No autorizado
- `404` - Recurso no encontrado
- `500` - Error interno del servidor

### 6. Logging

```python
import logging

logging.info("Información general")
logging.warning("Advertencia")
logging.error("Error con contexto")
logging.exception("Error con stack trace")
```

### 7. Cálculos Financieros

- Todos los precios se almacenan en **centavos** (integer)
- Se dividen por 100 solo al mostrar al usuario
- El IVA se calcula como: `base_amount = total / (1 + IVA_PERCENTAGE/10000)`
- El fee de servicio se calcula como porcentaje del precio del ticket

#### Configuración del IVA

La variable de entorno `IVA_PERCENTAGE` es un número entero entre 0 y 10000 donde:

| Valor | Porcentaje Real |
|-------|-----------------|
| `1600` | 16% |
| `500` | 5% |
| `2100` | 21% |
| `10000` | 100% |

> **Formato:** Similar a los precios en centavos, `IVA_PERCENTAGE = 1600` significa 16.00%

#### Fórmulas

```python
# Cálculo de IVA (donde total incluye IVA)
# IVA_PERCENTAGE está en formato entero: 1600 = 16%
IVA = IVA_PERCENTAGE / 10000  # ej: 1600/10000 = 0.16
base_amount = total / (1 + IVA)  # ej: total / 1.16
iva_amount = total - base_amount
```

### 8. Tasa de Cambio

- La tasa de cambio BsD/USD se obtiene de APIs externas
- Se almacena en centavos en `customer.BsDExchangeRate`
- Fuentes: `ve.dolarapi.com` (principal) y `api.dolarvzla.com` (respaldo)

---

## Bancos Venezolanos Soportados

El sistema soporta los siguientes bancos para PagoMóvil:

| Banco | Código |
|-------|--------|
| BANCO DE VENEZUELA | 0102 |
| BANCO VENEZOLANO DE CREDITO | 0104 |
| BANCO MERCANTIL | 0105 |
| BBVA PROVINCIAL | 0108 |
| BANCARIBE | 0114 |
| BANCO EXTERIOR | 0115 |
| BANCO CARONI | 0128 |
| BANESCO | 0134 |
| BANCO SOFITASA | 0137 |
| BANCO PLAZA | 0138 |
| BANGENTE | 0146 |
| BANCO FONDO COMUN | 0151 |
| 100% BANCO | 0156 |
| DELSUR BANCO UNIVERSAL | 0157 |
| BANCO DEL TESORO | 0163 |
| BANCRECER | 0168 |
| R4 BANCO MICROFINANCIERO | 0169 |
| BANCO ACTIVO | 0171 |
| BANCAMIGA BANCO UNIVERSAL | 0172 |
| BANCO INTERNACIONAL DE DESARROLLO | 0173 |
| BANPLUS | 0174 |
| BANCO DIGITAL DE LOS TRABAJADORES | 0175 |
| BANFANB | 0177 |
| N58 BANCO DIGITAL | 0178 |
| BANCO NACIONAL DE CREDITO | 0191 |

---

## Patrones de Validación

### Email
```python
email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
```

### Teléfono (E.164)
```python
phone_pattern = re.compile(r'^\+?[1-9]\d{1,14}$')
```

### Cédula Venezolana
```python
cedula_pattern = re.compile(r'^[EV]{1}\d{1,8}$')
```

### Teléfono Venezolano
```python
venezuelan_phone_pattern = re.compile(r'^(?:0412|0422|0414|0424|0416|0426)\d{7}$')
```

---

## Métodos de Pago

### USD
- `credit_card`
- `paypal`
- `stripe`
- `apple_pay`
- `google_pay`
- `zelle`
- `efectivo`
- `binance`

### BsD (Bolívares)
- `pagomovil`
- `debito_inmediato`
- `c2p`
- `pos`

---

## Notas de Mantenimiento

1. **Duplicación de Blueprint:** Existe una duplicación en líneas 27 y 33 (`events = Blueprint('events', __name__)`). Se recomienda eliminar la línea duplicada.

2. **Logs de Debug:** Las líneas con `print()` deben ser reemplazadas por `logging.debug()` en producción.

3. **Validación de Fecha de Expiración:** Los tickets tienen un campo `expires_at` que debe validarse antes de procesar pagos.

---

## Versión

- **Última actualización:** Febrero 2026
- **Versión del documento:** 1.0.0
