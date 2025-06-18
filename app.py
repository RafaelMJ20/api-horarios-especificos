from flask import Flask, jsonify, request
import requests
from requests.auth import HTTPBasicAuth
from flask_cors import CORS
from librouteros import connect
import datetime
import logging

# Configurar logging para depuración
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración del MikroTik
MIKROTIK_HOST = 'http://192.168.88.1'
MIKROTIK_API_HOST = '192.168.88.1'
USERNAME = 'admin'
PASSWORD = '1234567890'
API_PORT = 8728

def get_api():
    try:
        connection = connect(
            username=USERNAME,
            password=PASSWORD,
            host=MIKROTIK_API_HOST,
            port=API_PORT
        )
        logger.debug("Conexión establecida con RouterOS")
        return connection
    except Exception as e:
        logger.error(f"Error al conectar con RouterOS: {str(e)}")
        raise

# API para programar acceso por IP en horarios específicos
@app.route('/programar', methods=['POST'])
def programar_acceso():
    data = request.get_json()
    ip = data.get('ip_address')
    hora_inicio = data.get('hora_inicio')  # Ej: "04:00:00"
    hora_fin = data.get('hora_fin')        # Ej: "06:00:00"
    dias = data.get('dias')                # Ej: "mon,tue,wed"

    if not all([ip, hora_inicio, hora_fin, dias]):
        return jsonify({'error': 'Faltan datos: ip_address, hora_inicio, hora_fin o dias'}), 400

    comment_base = f"Programado-{ip}"
    fecha_hoy = datetime.datetime.now().strftime('%b/%d/%Y')

    try:
        api = get_api()

        firewall = api.path('ip', 'firewall', 'filter')

        # 1. Regla de bloqueo (habilitada por defecto)
        firewall.add(
            chain='forward',
            **{'src-address': ip},
            action='drop',
            comment=f"{comment_base}-bloqueo",
            disabled='no'
        )

        # 2. Regla de aceptación (deshabilitada por defecto)
        firewall.add(
            chain='forward',
            **{'src-address': ip},
            action='accept',
            comment=f"{comment_base}-acceso",
            disabled='yes'
        )

        scheduler = api.path('system', 'scheduler')

        # Activar acceso (enable accept, disable drop)
        scheduler.add(
            name=f"activar-{ip}",
            **{
                'start-time': hora_inicio,
                'start-date': fecha_hoy,
                'interval': '1d',
                'on-event': f"""
/ip firewall filter enable [find comment="{comment_base}-acceso"];
/ip firewall filter disable [find comment="{comment_base}-bloqueo"];
""",
                'comment': f"Activar acceso {ip}",
                'policy': 'read,write,test',
                'disabled': 'no'
            }
        )

        # Desactivar acceso (disable accept, enable drop)
        scheduler.add(
            name=f"desactivar-{ip}",
            **{
                'start-time': hora_fin,
                'start-date': fecha_hoy,
                'interval': '1d',
                'on-event': f"""
/ip firewall filter disable [find comment="{comment_base}-acceso"];
/ip firewall filter enable [find comment="{comment_base}-bloqueo"];
""",
                'comment': f"Desactivar acceso {ip}",
                'policy': 'read,write,test',
                'disabled': 'no'
            }
        )

        return jsonify({'message': f'Reglas programadas exitosamente para {ip}'}), 200

    except Exception as e:
        logger.error(f"Error al programar regla: {str(e)}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
