from flask import Flask, jsonify, request
from flask_cors import CORS
from librouteros import connect
import datetime
import logging
import os

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

MIKROTIK_API_HOST = os.environ.get('MIKROTIK_API_HOST', '41fb-200-68-173-150.ngrok-free.app')
USERNAME = os.environ.get('MIKROTIK_USERNAME', 'admin')
PASSWORD = os.environ.get('MIKROTIK_PASSWORD', '1234567890')
API_PORT = int(os.environ.get('MIKROTIK_API_PORT', 8728))

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

    try:
        api = get_api()
        firewall = api.path('ip', 'firewall', 'filter')

        firewall.add(
            chain='forward',
            **{'src-address': ip},
            action='drop',
            comment=f"{comment_base}-bloqueo",
            disabled='no'
        )

        firewall.add(
            chain='forward',
            **{'src-address': ip},
            action='accept',
            comment=f"{comment_base}-acceso",
            disabled='yes'
        )

        scheduler = api.path('system', 'scheduler')

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
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
