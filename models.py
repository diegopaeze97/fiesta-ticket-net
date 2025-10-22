from extensions import db
from sqlalchemy import Table, Column, Integer, ForeignKey, String, Float, Boolean, Date, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta

class Revoked_tokens(db.Model):
    __tablename__='revoked_tokens'
    id = db.Column("id", db.Integer, primary_key=True)
    tokens = db.Column("revoked_tokens", db.String)

class EventsUsers(db.Model):
    __tablename__ = 'events_users'

    CustomerID = Column(Integer, primary_key=True)
    FirstName = Column(String)
    LastName = Column(String)
    Email = Column(String)
    Identification = Column(String)
    Password = Column(String)
    PhoneNumber = Column(String)
    MainPicture = Column(String)
    cleared = Column(String) #status del usuario: bloqueado, eliminado, verificado o no verificado.
    strikes= Column(Integer) #contador de cantidad de intentos de inicio de sesion con contrasena errada
    verify_token = Column(String) #token unico que sirve para modificar la contrasena
    recovery_token = Column(String) #token unico que sirve para modificar email
    birthday = Column(Date)
    Gender = Column(String)
    Joindate = Column(Date)
    role = Column(String)
    status = Column(String)
    CreatedBy = Column(String)
    LastVerificationAttempt = Column(DateTime)
    BsDExchangeRate = Column(Integer)  # tasa de cambio en bolivares al momento del registro o ultima actualizacion

class Active_tokens(db.Model): #tokens de inicio de sesion expirados
    __tablename__='active_tokens'
    id = Column(Integer, primary_key=True)
    CustomerID = Column(Integer)
    jti = Column(String)
    CreatedAt = Column(DateTime(timezone=True), default=datetime.now)
    ExpiresAt = Column(DateTime(timezone=True), default=datetime.now() + timedelta(days=30))  # Expira en 30 días

class VerificationCode(db.Model):
    __tablename__='verification_code'
    id = Column(Integer, primary_key=True)
    email = Column(String(120), nullable=False)
    code = Column(String(128), nullable=False)
    attempt_time = Column(DateTime, default=datetime.now)

class VerificationAttempt(db.Model):
    __tablename__='verification_attempt'
    id = Column(Integer, primary_key=True)
    email = Column(String(120), nullable=False)
    attempt_time = Column(DateTime, default=datetime.now)
    success = Column(Boolean, default=False)

# Tabla para los lugares (ej: estadios, teatros)
class Venue(db.Model):
    __tablename__ = 'venues'

    venue_id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    address = Column(String(500), nullable=False)
    city = Column(String(100), nullable=False)
    
    # Relación one-to-many con la tabla Events
    events = relationship('Event', back_populates='venue')
    # Relación one-to-many con la tabla Sections
    sections = relationship('Section', back_populates='venue')

# Tabla para los eventos
class Event(db.Model):
    __tablename__ = 'events_ft'

    event_id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(String(1000))
    date = Column(Date, nullable=False)
    date_string = Column(String(255), nullable=False)
    hour_string = Column(String(255), nullable=False)
    venue_id = Column(Integer, ForeignKey('venues.venue_id'), nullable=False)
    created_by = Column(String(255), nullable=False)
    financiamientos = Column(String(50))
    items_to_sell = Column(String(100)) # Boletos|Pasajes|Hospedaje
    Type = Column(String) # Espectaculo o Paquete Turistico
    SVGmap = Column(String) # Mapa SVG del lugar, si aplica
    mainImage = Column(String(500))
    bannerImage = Column(String(500))
    active = Column(Boolean, default=True)
    event_id_provider = Column(Integer) # ID del evento en el proveedor externo (Tickera) #solo si aplica (API)
    event_provider = Column(Integer) # ID del proveedor externo (Tickera)
    Fee = Column(Integer) # Tarifa del evento
    
    # Relación one-to-one con la tabla Venue
    venue = relationship('Venue', back_populates='events')
    # Relación one-to-many con la tabla Tickets
    tickets = relationship('Ticket', back_populates='event')

# Tabla para las secciones dentro de un lugar (ej: Gradería, VIP)
class Section(db.Model):
    __tablename__ = 'sections'

    section_id = Column(Integer, primary_key=True)
    venue_id = Column(Integer, ForeignKey('venues.venue_id'), nullable=False)
    name = Column(String(100), nullable=False)

    # Relación one-to-one con la tabla Venue
    venue = relationship('Venue', back_populates='sections')
    # Relación one-to-many con la tabla Seats
    seats = relationship('Seat', back_populates='section')

# Tabla para los asientos individuales
class Seat(db.Model):
    __tablename__ = 'seats'

    seat_id = Column(Integer, primary_key=True)
    section_id = Column(Integer, ForeignKey('sections.section_id'), nullable=False)
    row = Column(String(50))
    number = Column(Integer)
    
    # Relación one-to-one con la tabla Section
    section = relationship('Section', back_populates='seats')
    # Relación one-to-many con la tabla Tickets
    tickets = relationship('Ticket', back_populates='seat')

# Tabla para los tickets
class Ticket(db.Model):
    __tablename__ = 'tickets'

    ticket_id = Column(Integer, primary_key=True)
    ticket_id_provider = Column(Integer)
    sale_id = Column(Integer, ForeignKey('sales.sale_id'), nullable=True) # Enlaza con la tabla Sales
    event_id = Column(Integer, ForeignKey('events_ft.event_id'), nullable=False)
    seat_id = Column(Integer, ForeignKey('seats.seat_id'), nullable=False)
    price = Column(Integer, nullable=False)
    status = Column(String(50), default='disponible') # 'pagado', 'pendiente', 'cancelado'
    availability_status = Column(String(50), default='disponible') # 'disponible', 'vendido', 'usado'
    customer_id = Column(Integer, ForeignKey('events_users.CustomerID'), nullable=True) # Enlaza con  tabla Customer
    creation_date = Column(Date, nullable=False, default=db.func.current_date())
    emission_date = Column(Date, nullable=True)
    canjeo_date = Column(DateTime, nullable=True)
    created_by = Column(Integer)
    last_modified = Column(Date, nullable=False, default=db.func.current_date())
    fee = Column(Integer, default=0)  # Fee de Tickera
    discount = Column(Integer, default=0) # descuento
    saleLink = Column(String(150))
    saleLocator = Column(String(6))
    QRlink = Column(String(200))
    blockedBy= Column(String(200))
    expires_at = Column(DateTime)

    # Relación one-to-one con la tabla Event
    event = relationship('Event', back_populates='tickets')
    # Relación one-to-one con la tabla Seat
    seat = relationship('Seat', back_populates='tickets')
    # Relación one-to-one con la tabla Customer (tu tabla de usuarios)
    customer = relationship('EventsUsers', backref='tickets')
    # Relación one-to-one con la tabla Sales
    sale = relationship('Sales', back_populates='tickets')

class Financiamientos(db.Model):
    __tablename__ = 'financiamientos'

    FinanciamientoID = Column(Integer, primary_key=True)
    FinanciamientoName = Column(String, nullable=False) #nombre del financiamiento
    Type = Column(String, nullable=False)  # 'reserva' o 'por_cuotas'
    NumeroCuotas = Column(Integer)  # ahora es int, más lógico para cálculos
    Intervalo = Column(Integer)  # en días/semanas/meses según tu lógica
    PorcentajeInicial = Column(Integer)
    MontoInicial = Column(Integer)
    MontoInicialFijo = Column(Boolean, nullable=False)
    Deadline = Column(Date)

    # Relación con la tabla Sales
    sales = relationship('Sales', back_populates='financiamiento_rel')


class Sales(db.Model):
    __tablename__ = 'sales'

    sale_id = Column(Integer, primary_key=True)
    ticket_ids = Column(String(50), nullable=False)
    price = Column(Integer, nullable=False)
    paid = Column(Integer, nullable=False)
    due_dates = Column(String(1000)) #date|amount|boolean||date|amount|boolean
    user_id = Column(Integer, ForeignKey('events_users.CustomerID'), nullable=True)
    items_liberados = Column(String(500)) #boleto|boleto|boleto|boleto
    items_por_liberar = Column(String(500)) #boleto|boleto|boleto|boleto
    status = Column(String(50), default='decontado')  # 'reserva', 'por cuotas', 'decontado', 'cancelado
    financiamiento = Column(Integer, ForeignKey('financiamientos.FinanciamientoID'), nullable=True)
    creation_date = Column(Date, nullable=False, default=db.func.current_date())
    created_by = Column(Integer)
    last_modified = Column(Date, onupdate=db.func.current_date())
    saleLink = Column(String(150))
    saleLocator = Column(String(6))
    StatusFinanciamiento = Column(String(60)) # al dia, retrasado, pagado
    event = Column(Integer, ForeignKey('events_ft.event_id'), nullable=False)
    fee = Column(Integer, default=0)  # Fee de Tickera
    discount = Column(Integer, default=0) # descuento
    ContactPhoneNumber = Column(String(20))  # número de teléfono de contacto para la venta

    # Relaciones
    customer = relationship('EventsUsers', backref='sales')
    financiamiento_rel = relationship('Financiamientos', back_populates='sales')
    event_rel = relationship('Event', backref='sales')
    tickets = relationship('Ticket', back_populates='sale')

class Logs(db.Model):
    __tablename__ = 'logs'

    LogID = Column(Integer, primary_key=True)
    UserID = Column(Integer, ForeignKey('events_users.CustomerID'), nullable=True)
    Type = Column(String) # sale, ticket, user, financiamiento, venta
    Timestamp = Column(Date, nullable=False, default=db.func.current_date())
    Details = Column(String)
    TicketID = Column(Integer, ForeignKey('tickets.ticket_id'), nullable=True)
    SaleID = Column(Integer, ForeignKey('sales.sale_id'), nullable=True)

    # Relaciones
    customer = relationship('EventsUsers', backref='logs')
    ticket = relationship('Ticket', backref='logs')
    sale = relationship('Sales', backref='logs')

class Payments(db.Model):
    __tablename__ = 'payments'

    PaymentID = Column(Integer, primary_key=True)
    SaleID = Column(Integer, ForeignKey('sales.sale_id'), nullable=False)
    Amount = Column(Integer, nullable=False)
    PaymentMethod = Column(String, nullable=False)  # 'credit_card', 'bank_transfer', etc.
    wallet = Column(String)  # 'paypal', 'stripe', lauraencinoza, etc.
    Reference = Column(String)  # referencia de pago
    MontoBS = Column(Integer)  # monto en bolivares
    Bank = Column(String)  # banco desde donde se hizo el pago
    PhoneNumber = Column(String)  # numero de telefono del comprador
    Status = Column(String, default='pendiente')  # 'approved', 'pending', 'rejected'
    PaymentDate = Column(Date, nullable=False, default=db.func.current_date)
    ApprovedBy = Column(Integer, ForeignKey('events_users.CustomerID'), nullable=True) #quien aprobo el pago
    CreatedBy = Column(Integer, ForeignKey('events_users.CustomerID'), nullable=True) #quien creo el registro del pago
    ApprovalDate = Column(Date)

    # Relación con la tabla Sales
    sale = relationship('Sales', backref='payments')
    approvedby = relationship('EventsUsers', foreign_keys=[ApprovedBy], backref='approved_payments')
    createdby = relationship('EventsUsers', foreign_keys=[CreatedBy], backref='created_payments')


class Providers(db.Model):
    __tablename__ = 'providers'

    ProviderID = Column(Integer, primary_key=True)
    TickeraUsername = Column(String, nullable=True)
    ProviderName = Column(String, nullable=True)
    TickeraAuthToken = Column(String, nullable=True)






