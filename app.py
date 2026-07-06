"""
Mapa interactivo de cámaras STS Security — Leaflet + Flask.
Sesiones privadas con ID largo + PIN opcional.
"""
import os, json, hashlib, secrets, time
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, abort, send_file
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('MAP_SECRET_KEY', 'sts-cotizador-2026')

DATA_DIR = Path("/app/data/mapas") if os.path.exists("/app/data") else Path(__file__).parent.parent / "data" / "mapas"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Rate limiting simple
_rate_limits = {}  # {ip: [timestamps]}


def rate_limit(max_req=30, window=60):
    """Simple rate limiter: max_req requests per window seconds per IP."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "0.0.0.0"
            now = time.time()
            _rate_limits.setdefault(ip, [])
            _rate_limits[ip] = [t for t in _rate_limits[ip] if now - t < window]
            if len(_rate_limits[ip]) >= max_req:
                abort(429)
            _rate_limits[ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _session_file(session_id: str) -> Path:
    """Usa hash completo (64 chars) para mayor seguridad."""
    safe = hashlib.sha256(session_id.encode()).hexdigest()
    return DATA_DIR / f"session_{safe}.json"


def _check_access(sf: Path, pin: str = None):
    """Verifica que la sesión exista, PIN coincida, no haya expirado, y no exceda límite de accesos."""
    if not sf.exists():
        abort(404)

    with open(sf) as f:
        data = json.load(f)

    # Expiración: 48h si está locked, 24h si no
    created = data.get("created_at", "")
    max_hours = 48 if data.get("locked") else 24
    if created:
        try:
            created_dt = datetime.fromisoformat(created)
            age_hours = (datetime.now() - created_dt).total_seconds() / 3600
            if age_hours > max_hours:
                sf.unlink()  # Auto-delete expired session
                abort(404)
        except ValueError:
            pass

    # Máximo 500 accesos totales por sesión
    access_count = data.get("access_count", 0)
    if access_count > 500:
        abort(404)
    data["access_count"] = access_count + 1
    with open(sf, 'w') as f:
        json.dump(data, f, indent=2)

    stored_pin = data.get("pin")
    if stored_pin and stored_pin != pin:
        abort(403)
    return data


@app.route('/')
def index():
    abort(404)  # Nada público — solo accesible con link directo


@app.route('/map/<session_id>')
@rate_limit(20, 60)
def map_session(session_id):
    pin = request.args.get("pin", "")
    sf = _session_file(session_id)

    if not sf.exists():
        return "<h2 style='text-align:center;margin-top:100px;font-family:sans-serif'>🔒 Sesión no encontrada o expirada.<br><small>Pedí un nuevo link a STS Security.</small></h2>", 404

    with open(sf) as f:
        data = json.load(f)

    if data.get("pin") and data.get("pin") != pin:
        return "<h2 style='text-align:center;margin-top:100px;font-family:sans-serif'>🔒 Acceso restringido.<br><small>Se requiere un PIN para ver este mapa.</small></h2>", 403

    # Limpiar PIN antes de pasarlo al frontend
    data.pop("pin", None)
    return render_template('map.html', session_data=json.dumps(data))


@app.route('/api/session/new', methods=['POST'])
@rate_limit(10, 60)
def create_session():
    """Crea una nueva sesión con ID largo y PIN opcional."""
    body = request.get_json() or {}
    session_id = secrets.token_hex(32)  # 64 caracteres

    data = {
        "session_id": session_id,
        "created_at": datetime.now().isoformat(),
        "property_name": body.get("property_name", ""),
        "pins": [],
        "map_center": body.get("map_center", {"lat": 9.9281, "lng": -84.0907}),
        "zoom": body.get("zoom", 15),
        "locked": False,
        "pin": body.get("pin", "") if body.get("pin") else None,
    }

    sf = _session_file(session_id)
    with open(sf, 'w') as f:
        json.dump(data, f, indent=2)

    return jsonify({
        "session_id": session_id,
        "url": f"/map/{session_id}",
        "has_pin": bool(data["pin"]),
    })


@app.route('/api/session/<session_id>', methods=['GET'])
@rate_limit(30, 60)
def get_session(session_id):
    pin = request.args.get("pin", "")
    sf = _session_file(session_id)
    data = _check_access(sf, pin)
    data.pop("pin", None)
    return jsonify(data)


@app.route('/api/session/<session_id>', methods=['POST'])
@rate_limit(30, 60)
def save_session(session_id):
    sf = _session_file(session_id)
    data = request.get_json()
    if not data:
        return jsonify({"error": "no data"}), 400

    # Mantener PIN si ya existe
    old_pin = None
    if sf.exists():
        with open(sf) as f:
            old = json.load(f)
        old_pin = old.get("pin")

    data["session_id"] = session_id
    data["updated_at"] = datetime.now().isoformat()
    if old_pin:
        data["pin"] = old_pin

    # Si está locked, solo permitir lectura
    if sf.exists():
        with open(sf) as f:
            old = json.load(f)
        if old.get("locked"):
            return jsonify({"error": "locked"}), 423

    with open(sf, 'w') as f:
        json.dump(data, f, indent=2)
    return jsonify({"status": "ok"})


@app.route('/api/session/<session_id>/lock', methods=['POST'])
@rate_limit(10, 60)
def lock_session(session_id):
    sf = _session_file(session_id)
    if not sf.exists():
        return jsonify({"error": "not found"}), 404

    with open(sf) as f:
        data = json.load(f)

    if data.get("locked"):
        return jsonify({"error": "already locked"}), 423

    data["locked"] = True
    data["locked_at"] = datetime.now().isoformat()
    with open(sf, 'w') as f:
        json.dump(data, f, indent=2)
    return jsonify({"status": "locked", "pin_count": len(data.get("pins", []))})


from staticmap import StaticMap, CircleMarker
from PIL import Image, ImageDraw, ImageFont
import io

@app.route('/api/session/<session_id>/screenshot', methods=['GET'])
def session_screenshot(session_id):
    """Genera una imagen satelital con pines numerados."""
    sf = _session_file(session_id)
    if not sf.exists():
        abort(404)

    with open(sf) as f:
        data = json.load(f)

    pins = data.get("pins", [])
    if not pins:
        abort(400)

    lats = [p["lat"] for p in pins]
    lngs = [p["lng"] for p in pins]
    center_lat = sum(lats) / len(lats)
    center_lng = sum(lngs) / len(lngs)

    span_lat = max(lats) - min(lats) if len(lats) > 1 else 0.002
    span_lng = max(lngs) - min(lngs) if len(lngs) > 1 else 0.002
    max_span = max(span_lat, span_lng) * 1.5 + 0.001
    zoom = max(1, min(20, int(15 - (max_span * 5000))))

    TILE_URL = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"
    sm = StaticMap(800, 500, url_template=TILE_URL)
    sm.zoom = zoom
    sm.center = [center_lng, center_lat]

    # Solo círculos de color (sin números aún)
    for pin in pins:
        color = pin.get("color", "#d49b2c")
        sm.add_marker(CircleMarker((pin["lng"], pin["lat"]), "white", 18))
        sm.add_marker(CircleMarker((pin["lng"], pin["lat"]), color, 15))

    image = sm.render()

    # Dibujar números con Pillow
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    except:
        font = ImageFont.load_default()

    for i, pin in enumerate(pins):
        # Convertir coordenadas a píxeles aproximados
        x = int((pin["lng"] - center_lng) * 800 * (2**zoom) / 360 + 400)
        y = int((center_lat - pin["lat"]) * 500 * (2**zoom) / 180 + 250)
        x = max(10, min(790, x))
        y = max(10, min(490, y))

        num = str(i + 1)
        bbox = draw.textbbox((0, 0), num, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        tx, ty = x - tw // 2, y - th // 2
        draw.text((tx, ty), num, fill="white", font=font)

    img_io = io.BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')


@app.route('/health')
def health():
    return jsonify({"status": "ok"})


# ═══════════ EVOLUTION API WEBHOOK RECEIVER ═══════════
import queue as qmod

_message_queue = qmod.Queue()

# Solo el grupo "Ubicaciones" — JID capturado
GRUPO_UBICACIONES = "120363354076179075@g.us"

@app.route('/api/webhooks/evolution', methods=['POST'])
def evolution_webhook():
    data = request.get_json(force=True, silent=True) or {}
    msg_data = data.get("data", data)
    jid = msg_data.get("key", {}).get("remoteJid", "")

    # Solo mensajes del grupo Ubicaciones
    if jid != GRUPO_UBICACIONES:
        return jsonify({"status": "ignored"})

    _message_queue.put({"timestamp": datetime.now().isoformat(), "data": data})
    return jsonify({"status": "received"})

@app.route('/api/webhooks/evolution/pending', methods=['GET'])
def get_pending_messages():
    messages = []
    while not _message_queue.empty():
        try:
            messages.append(_message_queue.get_nowait())
        except qmod.Empty:
            break
    return jsonify({"messages": messages, "count": len(messages)})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=False)

