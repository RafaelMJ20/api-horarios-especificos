from flask import Flask, jsonify, request
import os
import requests
from requests.auth import HTTPBasicAuth
from flask_cors import CORS
import datetime
import logging
import urllib3

# Silenciar warning de certificado self-signed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Variables de entorno
MIKROTIK_HOST = os.environ.get('MIKROTIK_HOST', 'https://f12c-2605-59c8-74d2-e610-00-c8b.ngrok-free.app')
USERNAME = os.environ.get('MIKROTIK_USER', 'admin')
PASSWORD = os.environ.get('MIKROTIK_PASSWORD', '1234567890')
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 10))

def verify_mikrotik_connection():
    test_url = f"{MIKROTIK_HOST}/rest/system/resource"
    try:
        logger.info(f"Verificando conexión con MikroTik en: {MIKROTIK_HOST}")
        resp = requests.get(
            test_url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        resp.raise_for_status()
        logger.info("Conexión exitosa con MikroTik")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error al conectar con MikroTik: {str(e)}")
        return False

@app.route('/programar', methods=['POST'])
def programar_acceso():
    data = request.get_json()
    ip = data.get('ip_address')
    hora_inicio = data.get('hora_inicio')
    hora_fin = data.get('hora_fin')
    dias = data.get('dias')

    if not all([ip, hora_inicio, hora_fin, dias]):
        return jsonify({'error': 'Faltan datos: ip_address, hora_inicio, hora_fin o dias'}), 400

    comment_base = f"Programado-{ip}"
    fecha_hoy = datetime.datetime.now().strftime('%Y-%m-%d')
    auth = HTTPBasicAuth(USERNAME, PASSWORD)

    if not verify_mikrotik_connection():
        return jsonify({'error': 'No hay conexión con MikroTik'}), 500

    firewall_url = f"{MIKROTIK_HOST}/rest/ip/firewall/filter"
    scheduler_url = f"{MIKROTIK_HOST}/rest/system/scheduler"

    try:
        # 1. Regla de bloqueo
        payload_block = {
            "chain": "forward",
            "src-address": ip,
            "action": "drop",
            "comment": f"{comment_base}-bloqueo",
            "disabled": "false"
        }
        resp_block = requests.post(firewall_url, json=payload_block, auth=auth, verify=False, timeout=REQUEST_TIMEOUT)
        logger.debug(f"Resp firewall drop: {resp_block.status_code} {resp_block.text}")

        # 2. Regla de aceptación
        payload_accept = {
            "chain": "forward",
            "src-address": ip,
            "action": "accept",
            "comment": f"{comment_base}-acceso",
            "disabled": "true"
        }
        resp_accept = requests.post(firewall_url, json=payload_accept, auth=auth, verify=False, timeout=REQUEST_TIMEOUT)
        logger.debug(f"Resp firewall accept: {resp_accept.status_code} {resp_accept.text}")

        # 3. Scheduler para activar acceso
        on_event_activar = (
            f'/ip firewall filter enable [find comment="{comment_base}-acceso"];'
            f'/ip firewall filter disable [find comment="{comment_base}-bloqueo"];'
        )
        payload_sched_start = {
            "name": f"activar-{ip}",
            "start-time": hora_inicio,
            "start-date": fecha_hoy,
            "interval": "24:00:00",
            "on-event": on_event_activar,
            "comment": f"Activar acceso {ip}",
            "policy": "read,write,policy,test",
            "disabled": "false"
        }
        resp_sched_start = requests.post(
            scheduler_url,
            json=payload_sched_start,
            auth=auth,
            verify=False,
            timeout=REQUEST_TIMEOUT
        )
        logger.debug(f"Resp scheduler activar: {resp_sched_start.status_code} {resp_sched_start.text}")

        # 4. Scheduler para desactivar acceso
        on_event_desactivar = (
            f'/ip firewall filter disable [find comment="{comment_base}-acceso"];'
            f'/ip firewall filter enable [find comment="{comment_base}-bloqueo"];'
        )
        payload_sched_stop = {
            "name": f"desactivar-{ip}",
            "start-time": hora_fin,
            "start-date": fecha_hoy,
            "interval": "24:00:00",
            "on-event": on_event_desactivar,
            "comment": f"Desactivar acceso {ip}",
            "policy": "read,write,policy,test",
            "disabled": "false"
        }
        resp_sched_stop = requests.post(
            scheduler_url,
            json=payload_sched_stop,
            auth=auth,
            verify=False,
            timeout=REQUEST_TIMEOUT
        )
        logger.debug(f"Resp scheduler desactivar: {resp_sched_stop.status_code} {resp_sched_stop.text}")

        # Validar que todos sean 2xx
        responses = [resp_block, resp_accept, resp_sched_start, resp_sched_stop]
        for resp in responses:
            if resp.status_code >= 400:
                return jsonify({"error": f"Error MikroTik: {resp.status_code}", "detalle": resp.text}), 500

        return jsonify({'message': f'Reglas programadas exitosamente para {ip}'}), 200

    except Exception as e:
        logger.error(f"Error al programar regla: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
