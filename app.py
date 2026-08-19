"""
Suite ENS — Plataforma de Herramientas de Ciberseguridad
Login + panel + herramientas originales + motores Python reales
"""
import os
import re
import secrets
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, flash, send_file
)

try:
    import tls_checker
except Exception as e:
    print("tls_checker no disponible:", e)
    tls_checker = None

try:
    import threatintel
except Exception as e:
    print("threatintel no disponible:", e)
    threatintel = None

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "tools")

USUARIO_ADMIN = os.environ.get("ADMIN_USER", "admin")
PASS_ADMIN = os.environ.get("ADMIN_PASS")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

if not PASS_ADMIN:
    PASS_ADMIN = secrets.token_urlsafe(12)


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


# ── Catálogo de herramientas ──
HERRAMIENTAS = {
    "metalimpio": {"nombre": "MetaLimpio ENS", "norma": "CCN-STIC-835 · [mp.info.5]",
                   "desc": "Borrado de metadatos en documentos", "archivo": "metalimpio.html"},
    "anonimizador": {"nombre": "AnonimizadorPD", "norma": "PDPC/AEPD · RGPD Art. 4(1)",
                     "desc": "Anonimización de datos personales", "archivo": "anonimizador.html"},
    "passpolicy": {"nombre": "PassPolicy ENS", "norma": "CCN-STIC-807 · CCN-STIC-140",
                   "desc": "Verificación y generación de contraseñas", "archivo": "passpolicy.html"},
    "securevault": {"nombre": "CCN SecureVault", "norma": "CCN-STIC-807 · CAT-R",
                    "desc": "Cifrado local de archivos AES-256-GCM", "archivo": "securevault.html"},
    "tls_checker": {"nombre": "TLS Privacy Checker", "norma": "RGPD · LOPD-GDD",
                    "desc": "Verificador REAL de cifrado TLS/SSL con mapeo RGPD",
                    "activa_real": True},
    "envio_pass": {"nombre": "Envío Seguro de Contraseñas", "norma": "CCN-STIC-807",
                   "desc": "Envío de credenciales mediante enlaces cifrados de un solo uso",
                   "disponible": False},
    "ciberlog": {"nombre": "CiberLog ENS", "norma": "CCN-STIC-817 · ENS art. 24",
                 "desc": "Gestión y notificación de ciberincidentes", "archivo": "ciberlog.html"},
    "cambiolog": {"nombre": "CambioLog ENS", "norma": "ENS op.exp.5 · RD 311/2022",
                  "desc": "Gestión del cambio con trazabilidad RSEG", "archivo": "cambiolog.html"},
    "biacalc": {"nombre": "BIACalc", "norma": "Continuidad de servicio · BIA",
                "desc": "Análisis de impacto, RTO/RPO y continuidad", "archivo": "biacalc.html"},
    "capacidad": {"nombre": "CapacidadENS", "norma": "ENS op.pl.4 · RD 311/2022",
                  "desc": "Dimensionamiento y Plan de Capacidad", "archivo": "capacidad.html"},
    "secinv": {"nombre": "SecInv", "norma": "Inventario de activos · ENS",
               "desc": "Catálogo de activos de seguridad", "archivo": "secinv.html"},
    "evaluacion": {"nombre": "Evaluación de Proyectos", "norma": "Análisis de riesgos CID · ENS",
                   "desc": "Evaluación temprana de nuevos proyectos", "archivo": "evaluacion.html"},
    "ticadq": {"nombre": "TICAdq", "norma": "Adquisiciones TIC · ENS",
               "desc": "Ciclo de adquisición TIC integral", "archivo": "ticadq.html"},
    "secmetrics": {"nombre": "SecMetrics", "norma": "ISO 27001 · NIST CSF · CIS Controls",
                   "desc": "Métricas de seguridad con constructor personalizado", "archivo": "secmetrics.html"},
    "intel": {"nombre": "Inteligencia de Amenazas", "norma": "CISA · NIST NVD · CCN-CERT · INCIBE",
              "desc": "Alertas REALES de fuentes oficiales + Watchlist + Telegram",
              "activa_real": True},
    "vulns": {"nombre": "Gestión de Vulnerabilidades", "norma": "Gestión de vulnerabilidades · ENS",
              "desc": "Escaneo, priorización y remediación de vulnerabilidades",
              "disponible": False},
    "securedev": {"nombre": "SecureDev Analyzer", "norma": "CCN-CERT BP/28 · OWASP 2025",
                  "desc": "Análisis estático de código seguro", "archivo": "securedev.html"},
    "checklist_bastionado": {"nombre": "Checklist de Bastionado", "norma": "ENS · CCN-STIC",
                             "desc": "Checklist auditable de bastionado con IA", "archivo": "checklist_bastionado.html"},
}


@app.route("/tool/<clave>")
@login_required
def herramienta(clave):
    info = HERRAMIENTAS.get(clave)
    if not info:
        return redirect(url_for("dashboard"))
    if not info.get("disponible", True):
        return render_template("herramienta.html", info=info)
    if info.get("activa_real"):
        if clave == "tls_checker":
            return render_template("tls_checker.html", info=info)
        if clave == "intel":
            return render_template("threatintel.html", info=info)
    ruta = os.path.join(TOOLS_DIR, info.get("archivo", ""))
    if os.path.exists(ruta):
        return send_file(ruta)
    return render_template("herramienta.html", info=info)


# ── Endpoints TLS Privacy Checker (análisis REAL) ──
@app.route("/tls/scan", methods=["POST"])
@login_required
def tls_scan():
    if tls_checker is None:
        return jsonify({"error": "Motor TLS no disponible"}), 500
    data = request.get_json() or {}
    dominio = (data.get("dominio") or "").strip().lower()
    dominio = re.sub(r"^https?://", "", dominio).split("/")[0]
    if not dominio or "." not in dominio:
        return jsonify({"error": "Dominio inválido"}), 400
    resultado = tls_checker.escanear_dominio(dominio)
    if OPENROUTER_API_KEY and not resultado.get("error"):
        resultado["resumen_ejecutivo"] = tls_checker.generar_resumen_con_ia(resultado, OPENROUTER_API_KEY)
        resultado["ia_disponible"] = True
    else:
        resultado["ia_disponible"] = False
    return jsonify(resultado)


# ── Endpoints ThreatIntel Pro (fuentes oficiales reales) ──
@app.route("/threatintel/feeds")
@login_required
def threatintel_feeds():
    if threatintel is None:
        return jsonify([])
    return jsonify(threatintel.get_feeds_normalized())


@app.route("/threatintel/alerts")
@login_required
def threatintel_alerts():
    if threatintel is None:
        return jsonify([])
    unread = request.args.get("unread", "false").lower() == "true"
    return jsonify(threatintel.get_alerts(unread))


@app.route("/threatintel/alerts/<alert_id>/read", methods=["POST"])
@login_required
def threatintel_mark_read(alert_id):
    if threatintel:
        threatintel.mark_alert_read(alert_id)
    return jsonify({"status": "ok"})


@app.route("/threatintel/watchlist", methods=["GET", "POST"])
@login_required
def threatintel_watchlist():
    if threatintel is None:
        return jsonify([])
    if request.method == "POST":
        data = request.get_json() or {}
        ioc = (data.get("ioc") or "").strip()
        if not ioc:
            return jsonify({"error": "IOC requerido"}), 400
        ioc_id = threatintel.add_to_watchlist(
            ioc, data.get("type", "domain"),
            data.get("severity", "medium"), data.get("notes", ""))
        return jsonify({"id": ioc_id, "status": "added"})
    return jsonify(threatintel.get_watchlist())


@app.route("/threatintel/watchlist/<ioc_id>", methods=["DELETE"])
@login_required
def threatintel_watchlist_delete(ioc_id):
    if threatintel:
        threatintel.remove_from_watchlist(ioc_id)
    return jsonify({"status": "deleted"})


@app.route("/threatintel/digest")
def threatintel_digest():
    """Lo dispara cron-job.org 1 vez al día para enviar el email resumen."""
    token = request.args.get("token", "")
    esperado = os.environ.get("DIGEST_TOKEN", "")
    if not esperado or not secrets.compare_digest(token, esperado):
        return jsonify({"error": "no autorizado"}), 403
    resultado = threatintel.send_daily_email_summary() if threatintel else "motor no disponible"
    return jsonify({"status": resultado})


if __name__ == "__main__":
    app.run(debug=False)
