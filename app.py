from flask import Flask, jsonify, request
import os
import requests
from requests.auth import HTTPBasicAuth
from flask_cors import CORS
import datetime
import logging

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
        response = requests.get(
            test_url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        response.raise_for_status()
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
    dias = data.get('dias')  # por ahora no se usa directamente en el scheduler

    if not all([ip, hora_inicio, hora_fin, dias]):
        return jsonify({'error': 'Faltan datos: ip_address, hora_inicio, hora_fin o dias'}), 400

    comment_base = f"Programado-{ip}"
    fecha_hoy = datetime.datetime.now().strftime('%Y-%m-%d')
    auth = HTTPBasicAuth(USERNAME, PASSWORD)

    if not verify_mikrotik_connection():
        return jsonify({'error': 'No hay conexión con MikroTik'}), 500

    try:
        # Endpoints
        firewall_url = f"{MIKROTIK_HOST}/rest/ip/firewall/filter"
        scheduler_url = f"{MIKROTIK_HOST}/rest/system/scheduler"

        # 1. Regla de bloqueo
        requests.post(
            firewall_url,
            json={
                "chain": "forward",
                "src-address": ip,
                "action": "drop",
                "comment": f"{comment_base}-bloqueo",
                "disabled": "false"
            },
            auth=auth,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )

        # 2. Regla de aceptación
        requests.post(
            firewall_url,
            json={
                "chain": "forward",
                "src-address": ip,
                "action": "accept",
                "comment": f"{comment_base}-acceso",
                "disabled": "true"
            },
            auth=auth,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )

        # 3. Programar activación
        on_event_activar = (
            f'/ip firewall filter enable [find comment="{comment_base}-acceso"];'
            f'/ip firewall filter disable [find comment="{comment_base}-bloqueo"];'
        )
        requests.post(
            scheduler_url,
            json={
                "name": f"activar-{ip}",
                "start-time": hora_inicio,
                "interval": "24:00:00",
                "on-event": on_event_activar,
                "comment": f"Activar acceso {ip}",
                "policy": "read,write,policy,test",
                "disabled": "false"
            },
            auth=auth,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )

        # 4. Programar desactivación
        on_event_desactivar = (
            f'/ip firewall filter disable [find comment="{comment_base}-acceso"];'
            f'/ip firewall filter enable [find comment="{comment_base}-bloqueo"];'
        )
        requests.post(
            scheduler_url,
            json={
                "name": f"desactivar-{ip}",
                "start-time": hora_fin,
                "interval": "24:00:00",
                "on-event": on_event_desactivar,
                "comment": f"Desactivar acceso {ip}",
                "policy": "read,write,policy,test",
                "disabled": "false"
            },
            auth=auth,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )

        return jsonify({'message': f'Reglas programadas exitosamente para {ip}'}), 200

    except Exception as e:
        logger.error(f"Error al programar regla: {str(e)}")
        return jsonify({'error': str(e)}), 500
        
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Iniciando servicio en puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
