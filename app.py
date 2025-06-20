from flask import Flask, jsonify, request
import requests
from requests.auth import HTTPBasicAuth
from flask_cors import CORS
from librouteros import connect
import datetime
import logging
import os
import sys
from functools import wraps

# =======================
# Configuración inicial
# =======================
app = Flask(__name__)
CORS(app)

# Configuración avanzada de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('api_mikrotik.log')
    ]
)
logger = logging.getLogger(__name__)

# =======================
# Configuración MikroTik (usar variables de entorno en producción)
# =======================
MIKROTIK_API_HOST = os.getenv('MIKROTIK_HOST', '192.168.88.1')
USERNAME = os.getenv('MIKROTIK_USER', 'admin')
PASSWORD = os.getenv('MIKROTIK_PASSWORD', '1234567890')
API_PORT = int(os.getenv('MIKROTIK_PORT', '8728'))

# =======================
# Funciones auxiliares
# =======================
def get_api_connection():
    """Establece conexión con MikroTik con logging detallado"""
    try:
        logger.info(f"Intentando conexión a {MIKROTIK_API_HOST}:{API_PORT}")
        connection = connect(
            username=USERNAME,
            password=PASSWORD,
            host=MIKROTIK_API_HOST,
            port=API_PORT,
            timeout=10
        )
        logger.info("Conexión exitosa con MikroTik")
        return connection
    except Exception as e:
        logger.error(f"Error de conexión: {str(e)}", exc_info=True)
        raise

def log_network_activity(ip, action):
    """Registra actividad de red en un archivo separado"""
    with open('network_activity.log', 'a') as f:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"{timestamp} - IP: {ip} - Acción: {action}\n")

# =======================
# Endpoints de la API
# =======================
@app.route('/programar', methods=['POST'])
def programar_acceso():
    """
    Programa acceso por IP en horarios específicos
    Ejemplo de body JSON:
    {
        "ip_address": "192.168.88.100",
        "hora_inicio": "08:00:00",
        "hora_fin": "18:00:00",
        "dias": "mon,tue,wed,thu,fri"
    }
    """
    data = request.get_json()
    
    # Validación de datos
    required_fields = ['ip_address', 'hora_inicio', 'hora_fin', 'dias']
    if not all(field in data for field in required_fields):
        logger.warning("Solicitud incompleta recibida")
        return jsonify({'error': 'Faltan campos requeridos'}), 400
    
    ip = data['ip_address']
    hora_inicio = data['hora_inicio']
    hora_fin = data['hora_fin']
    dias = data['dias']

    try:
        # Registrar intento de conexión
        log_network_activity(ip, f"Programando acceso {hora_inicio}-{hora_fin} dias:{dias}")
        
        api = get_api_connection()
        comment_base = f"Programado-{ip}-{datetime.datetime.now().strftime('%Y%m%d')}"

        # Configurar reglas de firewall
        firewall = api.path('ip', 'firewall', 'filter')
        
        # 1. Regla de bloqueo
        firewall.add(
            chain='forward',
            src_address=ip,
            action='drop',
            comment=f"{comment_base}-block",
            disabled='no'
        )
        logger.info(f"Regla de bloqueo creada para {ip}")

        # 2. Regla de permiso (inicialmente deshabilitada)
        firewall.add(
            chain='forward',
            src_address=ip,
            action='accept',
            comment=f"{comment_base}-allow",
            disabled='yes'
        )
        logger.info(f"Regla de permiso creada para {ip}")

        # Configurar programador
        scheduler = api.path('system', 'scheduler')

        # Tarea para habilitar acceso
        scheduler.add(
            name=f"enable-{ip}",
            start_time=hora_inicio,
            start_date=datetime.datetime.now().strftime('%b/%d/%Y'),
            interval='1d',
            on_event=f"""/ip firewall filter enable [find comment="{comment_base}-allow"];
                        /ip firewall filter disable [find comment="{comment_base}-block"];""",
            comment=f"Enable access for {ip}",
            policy='read,write,test',
            disabled='no'
        )
        logger.info(f"Tarea programada para habilitar acceso a {ip} a las {hora_inicio}")

        # Tarea para deshabilitar acceso
        scheduler.add(
            name=f"disable-{ip}",
            start_time=hora_fin,
            start_date=datetime.datetime.now().strftime('%b/%d/%Y'),
            interval='1d',
            on_event=f"""/ip firewall filter disable [find comment="{comment_base}-allow"];
                        /ip firewall filter enable [find comment="{comment_base}-block"];""",
            comment=f"Disable access for {ip}",
            policy='read,write,test',
            disabled='no'
        )
        logger.info(f"Tarea programada para deshabilitar acceso a {ip} a las {hora_fin}")

        return jsonify({
            'status': 'success',
            'message': f'Acceso programado para {ip} de {hora_inicio} a {hora_fin} días {dias}',
            'rules_created': [
                f"{comment_base}-block",
                f"{comment_base}-allow"
            ],
            'scheduled_tasks': [
                f"enable-{ip}",
                f"disable-{ip}"
            ]
        }), 200

    except Exception as e:
        logger.error(f"Error al programar acceso: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/status', methods=['GET'])
def status_check():
    """Endpoint para verificar estado del servicio"""
    try:
        api = get_api_connection()
        api.close()
        status = "connected"
    except Exception as e:
        status = f"disconnected: {str(e)}"
    
    return jsonify({
        'service': 'mikrotik-access-scheduler',
        'status': status,
        'timestamp': datetime.datetime.now().isoformat(),
        'mikrotik_host': MIKROTIK_API_HOST
    })

# =======================
# Configuración para despliegue
# =======================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Iniciando servicio en puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
