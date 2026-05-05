import os
import json
import jwt
import base64
import psycopg2
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from drift_detector import detect_drifts

KEY_PATH      = os.getenv("KEY_PATH",      "/app/keys/public_key.pem")
BASELINE_PATH = os.getenv("BASELINE_PATH", "/app/data/baseline.json")

app = Flask(__name__)


def load_rsa_keys():
    with open(KEY_PATH, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

try:
    PUBLIC_KEY = load_rsa_keys()
except FileNotFoundError:
    print("ERROR: No se encontraron las claves RSA. Asegúrate de generar las claves primero.")
    exit(1)


def get_db_connection():
    return psycopg2.connect(
        host=base64.b64decode(os.getenv("DB_HOST_B64")).decode(),
        user=base64.b64decode(os.getenv("DB_USER_B64")).decode(),
        password=base64.b64decode(os.getenv("DB_PASS_B64")).decode(),
        dbname=base64.b64decode(os.getenv("DB_NAME_B64")).decode(),
    )


def seed_baseline_if_empty(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM resources_baseline")
    if cur.fetchone()[0] == 0:
        with open(BASELINE_PATH, 'r', encoding='utf-8') as f:
            resources = json.load(f)
        for r in resources:
            cur.execute(
                "INSERT INTO resources_baseline (resource_id, type, config) VALUES (%s, %s, %s)",
                (r["resource_id"], r["type"], json.dumps(r)),
            )
        conn.commit()
    cur.close()


# ---------------------------------------------------------------------------
# Endpoints existentes
# ---------------------------------------------------------------------------

@app.route("/status")
def status():
    return jsonify({"status": "ok"}), 200


@app.route("/users")
def users():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT username FROM users")
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"users": [row[0] for row in data]})
    except Exception:
        return jsonify({"error": "Error al consultar usuarios"}), 500


@app.route("/admin/flag")
def admin_flag():
    B64_R = os.getenv("CAMPAING")
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Token inválido"}), 403

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        username = payload.get("user")
        role = payload.get("role")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT role FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()
        conn.close()

        valid = base64.b64decode(B64_R[::-1]).decode()
        if result and result[0] == valid and role == valid:
            return jsonify({
                "flag": "🎉 FLAG{congrats_you_made_it}",
                "message": "¡Bien hecho! Descubriste el acceso correcto.",
            })
        return jsonify({"error": "Token inválido"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 403


# ---------------------------------------------------------------------------
# Nuevos endpoints
# ---------------------------------------------------------------------------

@app.route("/resources/ingest", methods=["POST"])
def ingest_resources():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Body vacío o JSON inválido"}), 400

    resources = body if isinstance(body, list) else [body]

    for r in resources:
        if not r.get("resource_id") or not r.get("type"):
            return jsonify({"error": "Cada recurso debe tener 'resource_id' y 'type'"}), 400

    try:
        conn = get_db_connection()
        seed_baseline_if_empty(conn)

        cur = conn.cursor()
        all_drifts = []

        for r in resources:
            rid   = r["resource_id"]
            rtype = r["type"]

            # Upsert en resources_current (sin tocar created_at)
            cur.execute(
                """
                INSERT INTO resources_current (resource_id, type, config)
                VALUES (%s, %s, %s)
                ON CONFLICT (resource_id) DO UPDATE
                    SET config = EXCLUDED.config,
                        type   = EXCLUDED.type
                """,
                (rid, rtype, json.dumps(r)),
            )

            # Leer baseline desde BD (psycopg2 devuelve JSONB como dict)
            cur.execute(
                "SELECT config FROM resources_baseline WHERE resource_id = %s", (rid,)
            )
            row = cur.fetchone()
            if row:
                baseline = row[0] if isinstance(row[0], dict) else json.loads(row[0])
                new_drifts = detect_drifts(baseline, r)
            else:
                new_drifts = []

            # Replace: borrar drifts previos e insertar los nuevos
            cur.execute("DELETE FROM drifts WHERE resource_id = %s", (rid,))
            for d in new_drifts:
                cur.execute(
                    "INSERT INTO drifts (resource_id, type, description, severity)"
                    " VALUES (%s, %s, %s, %s)",
                    (d["resource_id"], d["type"], d["description"], d["severity"]),
                )

            all_drifts.extend(new_drifts)

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "processed": len(resources),
            "drifts_detected": len(all_drifts),
            "drifts": all_drifts,
        }), 200

    except Exception:
        return jsonify({"error": "Error interno al procesar recursos"}), 500


@app.route("/drifts/summary", methods=["GET"])
def drifts_summary():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT type, COUNT(*) FROM drifts GROUP BY type")
        by_type = {row[0]: row[1] for row in cur.fetchall()}

        cur.execute("SELECT severity, COUNT(*) FROM drifts GROUP BY severity")
        by_severity = {row[0]: row[1] for row in cur.fetchall()}

        cur.close()
        conn.close()

        return jsonify({
            "by_type": by_type,
            "by_severity": by_severity,
            "total": sum(by_type.values()),
        }), 200

    except Exception:
        return jsonify({"error": "Error interno al obtener resumen"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)