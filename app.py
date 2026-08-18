"""
Suite ENS — Plataforma de Herramientas de Ciberseguridad
Integración de herramientas originales SIN modificar + acceso con credenciales
"""
import os
import secrets
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, send_file
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Carpeta donde viven TUS HTML originales, intactos
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "tools")

# ── Credenciales (se configuran en Render, NUNCA en el código) ──
USUARIO_ADMIN = os.environ.get("ADMIN_USER", "admin")
PASS_ADMIN = os.environ.get("ADMIN_PASS")

if not PASS_ADMIN:
    PASS_ADMIN = secrets.token_urlsafe(12)
    print(f"⚠️  ADMIN_PASS no configurada. Contraseña temporal: {PASS_ADMIN}")


def login_required(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if not session.get("autenticado"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorada


@app.route("/")
def inicio():
    if session.get("autenticado"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("autenticado"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")
        if (secrets.compare_digest(usuario, USUARIO_ADMIN)
                and secrets.compare_digest(password, PASS_ADMIN)):
            session["autenticado"] = True
            session["usuario"] = usuario
            return redirect(url_for("dashboard"))
        flash("Credenciales incorrectas")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html",
                           usuario=session.get("usuario", "usuario"))


# ── Catálogo: cada herramienta apunta a TU HTML original ──
HERRAMIENTAS = {
    "metalimpio": {
        "nombre": "MetaLimpio ENS",
        "norma": "CCN-STIC-835 · [mp.info.5]",
        "desc": "Borrado de metadatos en documentos",
        "archivo": "metalimpio.html",
    },
    "passpolicy": {
        "nombre": "PassPolicy ENS",
        "norma": "CCN-STIC-807 · CCN-STIC-140",
        "desc": "Verificación y generación de contraseñas",
        "archivo": "passpolicy.html",
    },
    "anonimizador": {
        "nombre": "AnonimizadorPD",
        "norma": "PDPC/AEPD · RGPD Art. 4(1)",
        "desc": "Anonimización de datos personales",
        "archivo": "anonimizador.html",
    },
    "tls_checker": {
        "nombre": "TLS Privacy Checker",
        "norma": "RGPD · LOPD-GDD",
        "desc": "Verificador de cifrado TLS/SSL",
        "archivo": "tls_checker.html",
    },
}


@app.route("/tool/<clave>")
@login_required
def herramienta(clave):
    """Sirve tu HTML original TAL CUAL, protegido por login."""
    info = HERRAMIENTAS.get(clave)
    if not info:
        return redirect(url_for("dashboard"))
    ruta = os.path.join(TOOLS_DIR, info["archivo"])
    if os.path.exists(ruta):
        return send_file(ruta)
    return render_template("herramienta.html", info=info)


if __name__ == "__main__":
    app.run(debug=False)
