from flask import Flask, jsonify, request
from flask_cors import CORS
from librouteros import connect
import datetime
import logging
import os

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración del MikroTik
MIKROTIK_API_HOST = os.environ.get('MIKROTIK_API_HOST', 'f12c-2605-59c8-74d2-e610-00-c8b.ngrok-free.app')
USERNAME = os.environ.get('MIKROTIK_USER', 'admin')
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
        logger.debug(f"Conexión establecida con RouterOS {MIKROTIK_API_HOST}")
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

        # Regla de bloqueo
        firewall = api.path('ip', 'firewall', 'filter')
        firewall.add(
            chain='forward',
            src_address=ip,
            action='drop',
            comment=f"{comment_base}-bloqueo",
            disabled='no'
        )

        # Regla de aceptación (deshabilitada)
        firewall.add(
            chain='forward',
            src_address=ip,
            action='accept',
            comment=f"{comment_base}-acceso",
            disabled='yes'
        )

        scheduler = api.path('system', 'scheduler')

        # Scheduler activar
        scheduler.add(
            name=f"activar-{ip}",
            start_time=hora_inicio,
            start_date=fecha_hoy,
            interval='1d',
            on_event=(
                f'/ip firewall filter enable [find comment="{comment_base}-acceso"];\n'
                f'/ip firewall filter disable [find comment="{comment_base}-bloqueo"];'
            ),
            comment=f"Activar acceso {ip}",
            policy='read,write,policy,test',
            disabled='no'
        )

        # Scheduler desactivar
        scheduler.add(
            name=f"desactivar-{ip}",
            start_time=hora_fin,
            start_date=fecha_hoy,
            interval='1d',
            on_event=(
                f'/ip firewall filter disable [find comment="{comment_base}-acceso"];\n'
                f'/ip firewall filter enable [find comment="{comment_base}-bloqueo"];'
            ),
            comment=f"Desactivar acceso {ip}",
            policy='read,write,policy,test',
            disabled='no'
        )

        logger.info(f"Se han programado las reglas para {ip}")
        return jsonify({'message': f'Reglas programadas exitosamente para {ip}'}), 200

    except Exception as e:
        logger.error(f"Error al programar regla: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Iniciando servidor en puerto {port}")
    app.run(debug=False, host='0.0.0.0', port=port)
