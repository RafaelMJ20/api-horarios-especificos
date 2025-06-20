from flask import Flask, jsonify, request
import os
import requests
from requests.auth import HTTPBasicAuth
from flask_cors import CORS
import datetime
import logging
import urllib3

# Configuración y logging
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración MikroTik desde env
MIKROTIK_HOST = os.environ.get('MIKROTIK_HOST', 'https://tu-ngrok-or-host')
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
        return True
    except requests.RequestException as e:
        logger.error(f"Error al conectar con MikroTik: {e}")
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
    fecha_hoy = datetime.datetime.now().strftime('%b/%d/%Y')
    auth = HTTPBasicAuth(USERNAME, PASSWORD)

    if not verify_mikrotik_connection():
        return jsonify({'error': 'No hay conexión con MikroTik'}), 500

    firewall_url = f"{MIKROTIK_HOST}/rest/ip/firewall/filter"
    scheduler_url = f"{MIKROTIK_HOST}/rest/system/scheduler"

    try:
        # 1. Regla drop
        payload_block = {
            "chain": "forward",
            "src-address": ip,
            "action": "drop",
            "comment": f"{comment_base}-bloqueo",
            "disabled": "no"
        }
        resp_block = requests.post(firewall_url, json=payload_block, auth=auth, verify=False)
        logger.debug(f"Firewall drop: {resp_block.status_code} {resp_block.text}")

        # 2. Regla accept (deshabilitada)
        payload_accept = {
            "chain": "forward",
            "src-address": ip,
            "action": "accept",
            "comment": f"{comment_base}-acceso",
            "disabled": "yes"
        }
        resp_accept = requests.post(firewall_url, json=payload_accept, auth=auth, verify=False)
        logger.debug(f"Firewall accept: {resp_accept.status_code} {resp_accept.text}")

        # 3. Scheduler activar
        payload_sched_start = {
            "name": f"activar-{ip}",
            "start-time": hora_inicio,
            "start-date": fecha_hoy,
            "interval": "1d",
            "on-event": f'/ip firewall filter enable [find comment="{comment_base}-acceso"];\n/ip firewall filter disable [find comment="{comment_base}-bloqueo"];',
            "comment": f"Activar acceso {ip}",
            "policy": "read,write,policy,test",
            "disabled": "no"
        }
        resp_sched_start = requests.post(scheduler_url, json=payload_sched_start, auth=auth, verify=False)
        logger.debug(f"Scheduler activar: {resp_sched_start.status_code} {resp_sched_start.text}")

        # 4. Scheduler desactivar
        payload_sched_stop = {
            "name": f"desactivar-{ip}",
            "start-time": hora_fin,
            "start-date": fecha_hoy,
            "interval": "1d",
            "on-event": f'/ip firewall filter disable [find comment="{comment_base}-acceso"];\n/ip firewall filter enable [find comment="{comment_base}-bloqueo"];',
            "comment": f"Desactivar acceso {ip}",
            "policy": "read,write,policy,test",
            "disabled": "no"
        }
        resp_sched_stop = requests.post(scheduler_url, json=payload_sched_stop, auth=auth, verify=False)
        logger.debug(f"Scheduler desactivar: {resp_sched_stop.status_code} {resp_sched_stop.text}")

        # Verifica que todas sean OK
        for resp in [resp_block, resp_accept, resp_sched_start, resp_sched_stop]:
            if resp.status_code >= 400:
                return jsonify({"error": f"{resp.status_code}", "detalle": resp.text}), 500

        return jsonify({"message": f"Reglas programadas exitosamente para {ip}"}), 200

    except Exception as e:
        logger.error(f"Error programando acceso: {e}")
        return jsonify({"error": str(e)}), 500
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Iniciando servidor en puerto {port}")
    app.run(debug=False, host='0.0.0.0', port=port)
