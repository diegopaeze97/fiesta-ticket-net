

# El Modelo ticket 

Status que puede tener Ticket:
- pagado
- bloqueado
- pagado por verificar
- disponible
- en carrito
- pendiente pago

# El modelo Sale

Status puede tener uno de los siguientes valores:

- pendiente pago
- pagado por verificar
- aprobado
- cancelado

discount_ref se refiere a una relacion con la tabla Discounts

# El modelo EventUser 

Status puede tener uno de los siguientes valores

- verified
- unverified
- suspended
- deleted

# El modelo Discounts

class Discounts(db.Model):
    __tablename__ = 'discounts'

    DiscountID = Column(Integer, primary_key=True)
    Code = Column(String, nullable=False, unique=True)
    Description = Column(String)
    Percentage = Column(Integer, nullable=False)  # porcentaje de descuento
    FixedAmount = Column(Integer, nullable=False)  # monto fijo de descuento
    Active = Column(Boolean, default=True)
    UsageLimit = Column(Integer)  # limite de uso del codigo
    UsedCount = Column(Integer, default=0)  # contador de usos
    ValidFrom = Column(DateTime)
    ValidTo = Column(DateTime)
    ApplicableEvents = Column(String)  # lista de eventos donde aplica el descuento
    ApplicableUsers = Column(String)  # lista de usuarios donde aplica el descuento


    CreatedAt = Column(DateTime, default=db.func.current_timestamp())
    CreatedBy = Column(Integer, ForeignKey('events_users.CustomerID'), nullable=True)

    creator = relationship('EventsUsers', backref='created_discounts')

SI UsageLimit == 'infinite', puede usarse infinitamente
SI ApplicableEvents == 'all', el descuento aplica para todos los eventos
SI ApplicableUsers == 'all', el descuento aplica para todos los usuarios




#entendiendo el flujo de compra desde la interfaz del usuario:

RUTAS Y NOMENCLATURAS

/events/buy-tickets : para reservar asientos (buy) - solo bloquea por 10 minutos
/events/block-tickets : para reportar venta de asiento / bloqueo permanente (block) - bloqueado hasta confirmacion de compra por admin

####################
/events/buy-tickets:
####################

1. El usuario selecciona los tickets y agrega un codigo de descuento (opcional)

2. El sistema valida el codigo de descuento (validate_discount_code):
a - verifica que el codigo exista y este activo 
b - verifica que el codigo no haya excedido su UsageLimit
c - verifica que el codigo sea aplicable para el evento y usuario actual
d - crucial: la funcion valida si se estan reservando los asientos (buy) o si se trata de un bloqueo (block). 
Si se trata de un bloqueo, a expiration_date se le suman 10 minutos para evitar el escenario particular
en el que el usuario haya aplicado el codigo, haga el pago y este justamente se venza durante el checkout.

3. Si el descuento no es valido, la funcion devuelve false y el usuario debe intentar reservar de nuevo.

4. Se envia bloqueo al API de la productora (SI aplica)

5. Se actualiza status del ticket 

####################
/events/block-tickets:
####################

1. El usuario selecciona un metodo de pago
2. se valida el cupon de descuento. 
3. Se envia bloqueo al API de la productora (si aplica)
4. Se actualiza status del ticket: pagado, pendiente pago o pagado por verificar segun aplique



