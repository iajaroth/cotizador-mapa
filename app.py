"""
App web para colocar pines de cámaras sobre vista aérea (Leaflet + Flask).
Usa ESRI World Imagery (satelital gratuito, sin API key).
"""
import os, json, hashlib
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('MAP_SECRET_KEY', 'sts-cotizador-2026')

DATA_DIR = Path(__file__).parent.parent / "data" / "mapas"
DATA_DIR.mkdir(parents=True, exist_ok=True)


def _session_file(session_id: str) -> Path:
    safe = hashlib.sha256(session_id.encode()).hexdigest()[:16]
    return DATA_DIR / f"session_{safe}.json"


@app.route('/')
def index():
    return render_template('map.html')


@app.route('/map/<session_id>')
def map_session(session_id):
    sf = _session_file(session_id)
    if sf.exists():
        with open(sf) as f:
            data = json.load(f)
    else:
        data = {
            "session_id": session_id,
            "created_at": datetime.now().isoformat(),
            "property_name": "",
            "pins": [],
            "map_center": {"lat": 9.9281, "lng": -84.0907},
            "zoom": 15,
            "locked": False,
        }
    return render_template('map.html', session_data=json.dumps(data))


@app.route('/api/session/<session_id>', methods=['GET'])
def get_session(session_id):
    sf = _session_file(session_id)
    if sf.exists():
        with open(sf) as f:
            return jsonify(json.load(f))
    return jsonify({"error": "not found"}), 404


@app.route('/api/session/<session_id>', methods=['POST'])
def save_session(session_id):
    sf = _session_file(session_id)
    data = request.get_json()
    if not data:
        return jsonify({"error": "no data"}), 400
    data["session_id"] = session_id
    data["updated_at"] = datetime.now().isoformat()
    with open(sf, 'w') as f:
        json.dump(data, f, indent=2)
    return jsonify({"status": "ok"})


@app.route('/api/session/<session_id>/lock', methods=['POST'])
def lock_session(session_id):
    sf = _session_file(session_id)
    if not sf.exists():
        return jsonify({"error": "not found"}), 404
    with open(sf) as f:
        data = json.load(f)
    data["locked"] = True
    data["locked_at"] = datetime.now().isoformat()
    with open(sf, 'w') as f:
        json.dump(data, f, indent=2)
    return jsonify({"status": "locked", "pin_count": len(data.get("pins", []))})


@app.route('/health')
def health():
    return jsonify({"status": "ok"})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=False)
