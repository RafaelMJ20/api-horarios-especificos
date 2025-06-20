from flask import Flask, jsonify, request
from flask_cors import CORS
from librouteros import connect
import requests
from requests.auth import HTTPBasicAuth
import datetime
import logging
import os
import sys
import re
from typing import Dict, List, Optional

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
        logging.FileHandler('mikrotik_scheduler.log')
    ]
)
logger = logging.getLogger(__name__)

# =======================
# Configuración MikroTik (usar variables de entorno en producción)
# =======================
MIKROTIK_HOST = os.getenv('MIKROTIK_HOST', 'https://f12c-2605-59c8-74d2-e610-00-c8b.ngrok-free.app')
USERNAME = os.getenv('MIKROTIK_USER', 'admin')
PASSWORD = os.getenv('MIKROTIK_PASSWORD', '1234567890')
API_PORT = 8728
REQUEST_TIMEOUT = 10

# =======================
# Funciones de conexión mejoradas (REST + librouteros)
# =======================
def verify_mikrotik_connection() -> bool:
    """Verifica conexión usando REST API (para comprobación rápida)"""
    test_url = f"{MIKROTIK_HOST}/rest/system/resource"
    try:
        logger.info(f"Verificando conexión REST con MikroTik en: {MIKROTIK_HOST}")
        response = requests.get(
            test_url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            timeout=REQUEST_TIMEOUT,
            verify=False  # Solo para desarrollo con Ngrok sin certificado válido
        )
        response.raise_for_status()
        logger.info("Conexión REST exitosa con MikroTik")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error en conexión REST: {str(e)}")
        return False

def get_api_connection() -> 'Api':
    """Establece conexión usando librouteros (para operaciones reales)"""
    try:
        # Extraer hostname sin protocolo para librouteros
        hostname = MIKROTIK_HOST.replace('https://', '').replace('http://', '')
        
        logger.info(f"Conectando a MikroTik via librouteros en: {hostname}:{API_PORT}")
        
        connection = connect(
            username=USERNAME,
            password=PASSWORD,
            host=hostname,
            port=API_PORT,
            timeout=REQUEST_TIMEOUT,
            ssl=False  # Ngrok ya maneja SSL
        )
        logger.info("Conexión librouteros exitosa")
        return connection
    except Exception as e:
        logger.error(f"Error en conexión librouteros: {str(e)}", exc_info=True)
        raise

# =======================
# Funciones auxiliares mejoradas
# =======================
def validate_time_format(time_str: str) -> bool:
    """Valida formato HH:MM:SS"""
    return bool(re.match(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$', time_str))

def validate_days(days_str: str) -> bool:
    """Valida días de la semana (mon,tue,wed,...)"""
    valid_days = {'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'}
    days = days_str.split(',')
    return all(day.strip() in valid_days for day in days)

def cleanup_old_rules(api: 'Api', ip: str) -> Dict[str, int]:
    """Elimina reglas y programaciones antiguas para la misma IP"""
    counts = {'filter_rules': 0, 'scheduler_rules': 0}
    
    # Limpiar reglas de firewall antiguas
    firewall = api.path('ip', 'firewall', 'filter')
    for rule in firewall:
        if rule.get('src-address') == ip and "Programado" in rule.get('comment', ''):
            firewall.remove(id=rule['.id'])
            counts['filter_rules'] += 1
            logger.info(f"Eliminada regla firewall: {rule['.id']}")

    # Limpiar programaciones antiguas
    scheduler = api.path('system', 'scheduler')
    for task in scheduler:
        if f"Programado-{ip}" in task.get('name', ''):
            scheduler.remove(id=task['.id'])
            counts['scheduler_rules'] += 1
            logger.info(f"Eliminada tarea programada: {task['.id']}")

    return counts

# =======================
# Endpoint principal para programación
# =======================
@app.route('/schedule', methods=['POST'])
def schedule_access():
    """
    Programa acceso por IP en horarios específicos
    Ejemplo de body JSON:
    {
        "ip_address": "192.168.88.100",
        "start_time": "08:00:00",
        "end_time": "17:00:00",
        "days": "mon,tue,wed,thu,fri",
        "timezone": "America/Lima"  # Opcional
    }
    """
    data = request.get_json()
    
    # Validación de entrada
    required_fields = ['ip_address', 'start_time', 'end_time', 'days']
    if not all(field in data for field in required_fields):
        logger.warning("Solicitud incompleta recibida")
        return jsonify({'error': 'Faltan campos requeridos', 'required': required_fields}), 400

    ip = data['ip_address']
    start_time = data['start_time']
    end_time = data['end_time']
    days = data['days']
    timezone = data.get('timezone', 'UTC')

    # Validación de formatos
    if not validate_time_format(start_time):
        return jsonify({'error': 'Formato de hora inicio inválido (HH:MM:SS)'}), 400
    if not validate_time_format(end_time):
        return jsonify({'error': 'Formato de hora fin inválido (HH:MM:SS)'}), 400
    if not validate_days(days):
        return jsonify({'error': 'Días inválidos (usar: mon,tue,wed,etc.)'}), 400

    # Verificar conexión primero con REST
    if not verify_mikrotik_connection():
        return jsonify({'error': 'No se pudo verificar la conexión con MikroTik'}), 502

    try:
        api = get_api_connection()
        timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        base_comment = f"Programado-{ip}-{timestamp}"

        # Limpiar reglas antiguas para esta IP
        cleanup_counts = cleanup_old_rules(api, ip)
        logger.info(f"Reglas limpiadas: {cleanup_counts}")

        # Crear reglas de firewall
        firewall = api.path('ip', 'firewall', 'filter')
        
        # Regla de bloqueo (activa por defecto)
        block_rule = firewall.add(
            chain='forward',
            src_address=ip,
            action='drop',
            comment=f"{base_comment}-block",
            disabled='no'
        )
        logger.info(f"Regla de bloqueo creada: {block_rule}")

        # Regla de permiso (inactiva por defecto)
        allow_rule = firewall.add(
            chain='forward',
            src_address=ip,
            action='accept',
            comment=f"{base_comment}-allow",
            disabled='yes'
        )
        logger.info(f"Regla de permiso creada: {allow_rule}")

        # Configurar programador
        scheduler = api.path('system', 'scheduler')

        # Tarea para habilitar acceso
        enable_task = scheduler.add(
            name=f"enable-{ip}-{timestamp}",
            start_time=start_time,
            start_date=datetime.datetime.now().strftime('%Y-%m-%d'),
            interval=f"{days}",
            on_event=f"""/ip firewall filter enable [find comment="{base_comment}-allow"];
                        /ip firewall filter disable [find comment="{base_comment}-block"];""",
            comment=f"Habilitar acceso {ip} {start_time} {days}",
            policy='read,write,test',
            disabled='no'
        )
        logger.info(f"Tarea de habilitación creada: {enable_task}")

        # Tarea para deshabilitar acceso
        disable_task = scheduler.add(
            name=f"disable-{ip}-{timestamp}",
            start_time=end_time,
            start_date=datetime.datetime.now().strftime('%Y-%m-%d'),
            interval=f"{days}",
            on_event=f"""/ip firewall filter disable [find comment="{base_comment}-allow"];
                        /ip firewall filter enable [find comment="{base_comment}-block"];""",
            comment=f"Deshabilitar acceso {ip} {end_time} {days}",
            policy='read,write,test',
            disabled='no'
        )
        logger.info(f"Tarea de deshabilitación creada: {disable_task}")

        return jsonify({
            'status': 'success',
            'message': f'Acceso programado para {ip} de {start_time} a {end_time} días {days}',
            'timezone': timezone,
            'rules_created': {
                'block': f"{base_comment}-block",
                'allow': f"{base_comment}-allow"
            },
            'scheduled_tasks': {
                'enable': f"enable-{ip}-{timestamp}",
                'disable': f"disable-{ip}-{timestamp}"
            },
            'cleanup_counts': cleanup_counts,
            'connection_method': 'REST + librouteros via Ngrok'
        }), 200

    except Exception as e:
        logger.error(f"Error al programar acceso: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        if 'api' in locals():
            api.close()

# =======================
# Endpoints adicionales
# =======================
@app.route('/status', methods=['GET'])
def service_status():
    """Verifica estado del servicio usando REST"""
    connection_status = verify_mikrotik_connection()
    return jsonify({
        'status': 'active',
        'mikrotik_connection': connection_status,
        'timestamp': datetime.datetime.now().isoformat(),
        'connection_method': 'REST API'
    }), 200 if connection_status else 503

@app.route('/list-schedules', methods=['GET'])
def list_schedules():
    """Lista todas las programaciones activas usando librouteros"""
    try:
        api = get_api_connection()
        scheduler = api.path('system', 'scheduler')
        
        schedules = []
        for task in scheduler:
            if "Programado" in task.get('comment', ''):
                schedules.append({
                    'id': task.get('.id'),
                    'name': task.get('name'),
                    'comment': task.get('comment'),
                    'start_time': task.get('start-time'),
                    'interval': task.get('interval'),
                    'disabled': task.get('disabled') == 'true'
                })
        
        return jsonify({
            'schedules': schedules,
            'connection_method': 'librouteros'
        }), 200
    except Exception as e:
        logger.error(f"Error al listar programaciones: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        if 'api' in locals():
            api.close()

# =======================
# Inicialización
# =======================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Iniciando servicio en puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
