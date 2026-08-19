"""
Motor de Inteligencia de Amenazas — ThreatIntel Pro
Descarga fuentes oficiales (CISA KEV, NIST NVD, CCN-CERT, INCIBE) cada 15 min,
las compara con la Watchlist y genera alertas (web + Telegram + email diario).
"""
import os
import json
import hashlib
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
import feedparser

CACHE_DIR = "cache_threatintel"
DB_FILE = "threatintel.db"
SCAN_INTERVAL_MINUTES = 15

os.makedirs(CACHE_DIR, exist_ok=True)

FUENTES = {
    "cisa_kev": {"name": "CISA KEV", "country": "🇺🇸"},
    "nist_nvd": {"name": "NIST NVD", "country": "🇺🇸"},
    "ccn_cert": {"name": "CCN-CERT", "country": "🇪🇸"},
    "incibe":   {"name": "INCIBE-CERT", "country": "🇪🇸"},
}


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS watchlist (
        id TEXT PRIMARY KEY, ioc TEXT NOT NULL, type TEXT,
        severity TEXT DEFAULT 'medium', added_date TEXT, notes TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY, ioc TEXT, source TEXT, title TEXT,
        description TEXT, severity TEXT, detected_date TEXT, read INTEGER DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS feeds_cache (
        id TEXT PRIMARY KEY, source TEXT, title TEXT, description TEXT,
        published_date TEXT, iocs TEXT, severity TEXT, url TEXT)""")
    conn.commit()
    conn.close()


# ── Descarga de fuentes oficiales ─────────────────────────────
def fetch_cisa_kev():
    """Vulnerabilidades explotadas activamente (las más peligrosas)."""
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=30)
        r.raise_for_status()
        out = []
        for v in r.json().get("vulnerabilities", [])[:50]:
            out.append({
                "id": "cisa_" + v.get("cveID", ""),
                "source": "CISA KEV",
                "title": v.get("cveID", "CVE desconocido"),
                "description": v.get("shortDescription", ""),
                "published_date": v.get("dateAdded", ""),
                "iocs": [v.get("cveID", "")],
                "severity": "critical",
                "url": "https://nvd.nist.gov/vuln/detail/" + v.get("cveID", ""),
            })
        return out
    except Exception as e:
        print("Error CISA KEV:", e)
        return []


def fetch_nist_nvd():
    """CVEs publicados en las últimas 24 h."""
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=1)
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 50,
            }, timeout=30)
        r.raise_for_status()
        out = []
        for item in r.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            severity = "medium"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if metrics.get(key):
                    score = metrics[key][0].get("cvssData", {}).get("baseScore", 0)
                    severity = ("critical" if score >= 9 else "high" if score >= 7
                                else "medium" if score >= 4 else "low")
                    break
            out.append({
                "id": "nvd_" + cve_id,
                "source": "NIST NVD",
                "title": cve_id,
                "description": desc,
                "published_date": cve.get("published", ""),
                "iocs": [cve_id],
                "severity": severity,
                "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            })
        return out
    except Exception as e:
        print("Error NIST NVD:", e)
        return []


def fetch_rss(clave, url):
    """Boletines oficiales España (el servidor los convierte a JSON)."""
    try:
        feed = feedparser.parse(url)
        out = []
        for e in feed.entries[:30]:
            out.append({
                "id": clave + "_" + hashlib.md5(e.get("link", "").encode()).hexdigest()[:12],
                "source": FUENTES[clave]["name"],
                "title": e.get("title", ""),
                "description": e.get("summary", "")[:300],
                "published_date": e.get("published", e.get("updated", "")),
                "iocs": [],
                "severity": "medium",
                "url": e.get("link", ""),
            })
        return out
    except Exception as e:
        print(f"Error RSS {clave}:", e)
        return []


def scan_all_feeds():
    items = []
    items.extend(fetch_cisa_kev())
    items.extend(fetch_nist_nvd())
    items.extend(fetch_rss("ccn_cert", "https://www.ccn-cert.cni.es/component/banners/click/5"))
    items.extend(fetch_rss("incibe", "https://www.incibe.es/incibe-cert/alerta-temprana/avisos-seguridad/feed"))
    return items


# ── Persistencia y motor de alertas ───────────────────────────
def save_feeds_cache(items):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for i in items:
        c.execute("""INSERT OR REPLACE INTO feeds_cache
            (id, source, title, description, published_date, iocs, severity, url)
            VALUES (?,?,?,?,?,?,?,?)""",
                  (i["id"], i["source"], i["title"], i["description"],
                   i["published_date"], json.dumps(i["iocs"]), i["severity"], i["url"]))
    conn.commit()
    conn.close()


def check_watchlist_matches(items):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT ioc, severity FROM watchlist")
    watch = c.fetchall()
    conn.close()

    alerts = []
    for item in items:
        for ioc, sev in watch:
            texto = (item["title"] + " " + item["description"]).lower()
            if ioc.lower() in texto or any(ioc.lower() in x.lower() for x in item["iocs"]):
                alerts.append({
                    "id": hashlib.md5((item["id"] + ioc).encode()).hexdigest()[:16],
                    "ioc": ioc,
                    "source": item["source"],
                    "title": f"{ioc} detectado en {item['source']}",
                    "description": item["description"],
                    "severity": sev,
                    "detected_date": datetime.now(timezone.utc).isoformat(),
                    "read": 0,
                })
    return alerts


def save_alerts(alerts):
    if not alerts:
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for a in alerts:
        c.execute("""INSERT OR IGNORE INTO alerts
            (id, ioc, source, title, description, severity, detected_date, read)
            VALUES (?,?,?,?,?,?,?,?)""",
                  (a["id"], a["ioc"], a["source"], a["title"], a["description"],
                   a["severity"], a["detected_date"], a["read"]))
    conn.commit()
    conn.close()


# ── Notificaciones ────────────────────────────────────────────
def send_telegram_alert(alert):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        return
    try:
        msg = (f"🚨 ALERTA DE INTELIGENCIA\n\n{alert['title']}\n"
               f"🔍 IOC: {alert['ioc']}\n📡 Fuente: {alert['source']}\n"
               f"⚠ Severidad: {alert['severity'].upper()}\n\n"
               f"{alert['description'][:200]}")
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      json={"chat_id": chat, "text": msg}, timeout=10)
    except Exception as e:
        print("Error Telegram:", e)


def send_daily_email_summary():
    """Resumen diario por email (lo dispara cron-job.org una vez al día)."""
    api_key = os.environ.get("BREVO_API_KEY")
    mail_from = os.environ.get("EMAIL_FROM")
    mail_to = os.environ.get("EMAIL_TO")
    if not all([api_key, mail_from, mail_to]):
        return "email no configurado"

    alerts = get_alerts(unread_only=True)
    if not alerts:
        return "sin alertas"

    filas = "".join(
        f"<tr><td>{a['title']}</td><td>{a['source']}</td>"
        f"<td>{a['severity'].upper()}</td><td>{a['detected_date'][:10]}</td></tr>"
        for a in alerts)
    html = (f"<h2>🛡 Resumen diario de alertas — ThreatIntel Pro</h2>"
            f"<p>{len(alerts)} alerta(s) sin leer:</p>"
            f"<table border='1' cellpadding='8' cellspacing='0'>"
            f"<tr><th>Alerta</th><th>Fuente</th><th>Severidad</th><th>Fecha</th></tr>"
            f"{filas}</table>")
    try:
        requests.post("https://api.brevo.com/v3/smtp/email",
                      headers={"api-key": api_key, "Content-Type": "application/json"},
                      json={"sender": {"name": "ThreatIntel Pro", "email": mail_from},
                            "to": [{"email": mail_to}],
                            "subject": f"🚨 {len(alerts)} alertas de seguridad",
                            "htmlContent": html}, timeout=15)
        return "enviado"
    except Exception as e:
        print("Error email:", e)
        return "error"


# ── Escáner en segundo plano (cada 15 min) ────────────────────
def background_scanner():
    init_db()
    while True:
        try:
            print(f"[{datetime.now()}] Escaneando fuentes oficiales...")
            items = scan_all_feeds()
            save_feeds_cache(items)
            alerts = check_watchlist_matches(items)
            if alerts:
                save_alerts(alerts)
                for a in alerts:
                    send_telegram_alert(a)
        except Exception as e:
            print("Error scanner:", e)
        time.sleep(SCAN_INTERVAL_MINUTES * 60)


threading.Thread(target=background_scanner, daemon=True).start()


# ── Funciones que usa la API Flask ────────────────────────────
def get_feeds_normalized():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""SELECT id, source, title, description, published_date, iocs, severity, url
                 FROM feeds_cache ORDER BY published_date DESC LIMIT 100""")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "source": r[1], "title": r[2], "description": r[3],
             "published_date": r[4], "iocs": json.loads(r[5] or "[]"),
             "severity": r[6], "url": r[7]} for r in rows]


def get_alerts(unread_only=False):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    q = "SELECT * FROM alerts" + (" WHERE read=0" if unread_only else "") + \
        " ORDER BY detected_date DESC LIMIT 50"
    c.execute(q)
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "ioc": r[1], "source": r[2], "title": r[3], "description": r[4],
             "severity": r[5], "detected_date": r[6], "read": bool(r[7])} for r in rows]


def get_watchlist():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM watchlist ORDER BY added_date DESC")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "ioc": r[1], "type": r[2], "severity": r[3],
             "added_date": r[4], "notes": r[5]} for r in rows]


def add_to_watchlist(ioc, ioc_type, severity="medium", notes=""):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    ioc_id = hashlib.md5(ioc.encode()).hexdigest()[:16]
    c.execute("INSERT OR REPLACE INTO watchlist (id,ioc,type,severity,added_date,notes) VALUES (?,?,?,?,?,?)",
              (ioc_id, ioc, ioc_type, severity, datetime.now(timezone.utc).isoformat(), notes))
    conn.commit()
    conn.close()
    return ioc_id


def remove_from_watchlist(ioc_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM watchlist WHERE id=?", (ioc_id,))
    conn.commit()
    conn.close()


def mark_alert_read(alert_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE alerts SET read=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
