from factory import createApp
from extensions import db
import os

app = createApp()

if __name__ == '__main__':

    with app.app_context():  # Añade el contexto de la aplicación
        db.create_all()

    ssl_context_env = os.environ.get("SSL_CONTEXT")

    if ssl_context_env == "adhoc":
        ssl_context = "adhoc"
    elif ssl_context_env in ("", None, "none", "None"):
        ssl_context = None
    else:
        # En caso de que quieras usar tus propios certificados
        ssl_context = tuple(ssl_context_env.split(",")) if "," in ssl_context_env else None

    app.run(host=os.environ.get('HOST'), port=os.environ.get('PORT'), debug=os.environ.get('DEBUG'), ssl_context=ssl_context)
