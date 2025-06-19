from flask import Flask, render_template, jsonify, request, make_response, session, redirect, url_for, flash
from security_manager import SecurityManager
import logging
from datetime import datetime
import random
import os
import json
from functools import wraps
import time
import subprocess
import requests
import threading
import socket
import platform

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Set the playbooks directory path
playbooks_dir = r"C:\Users\gohil\OneDrive\Desktop\python\playbooks"

# Initialize managers
security_manager = SecurityManager()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Secret key for session management
app.secret_key = 'your_secret_key_here'

# Cache decorator
def cache_response(timeout=5):
    cache = {}
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            key = f.__name__ + str(args) + str(kwargs)
            if key in cache:
                result, timestamp = cache[key]
                if time.time() - timestamp < timeout:
                    return result
            result = f(*args, **kwargs)
            cache[key] = (result, time.time())
            return result
        return decorated_function
    return decorator

@app.before_request
def log_every_request():
    # Log every request path as a real log entry with more details
    security_manager.add_log(
        'INFO', 'web', f'Endpoint accessed: {request.path}',
        event_id='1000',
        process_id=os.getpid(),
        name=request.endpoint,
        host_id=request.remote_addr,
        destination=request.host,
        extra={'method': request.method}
    )

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    def get_ip_address():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = "Unavailable"
        return ip
    app.logger.info("Accessing Dashboard")
    security_manager.add_log('INFO', 'web', 'Dashboard accessed', event_id='1001', process_id=os.getpid(), name='index', host_id=request.remote_addr, destination=request.host)
    # Get system info, cpu, memory, threat for dashboard cards
    system_info = security_manager.system_info if hasattr(security_manager, 'system_info') else {}
    cpu = security_manager.get_cpu_usage() if hasattr(security_manager, 'get_cpu_usage') else {'current': 0}
    memory = security_manager.get_memory_usage() if hasattr(security_manager, 'get_memory_usage') else {'current': 0}
    threat = 'Normal'
    # Ensure hostname, os, and ip are always present and reliable
    hostname = system_info.get('hostname') or socket.gethostname()
    os_name = system_info.get('os') or (platform.system() + " " + platform.release())
    ip = get_ip_address()
    return render_template('index.html', system_info=system_info, cpu=cpu, memory=memory, threat=threat, hostname=hostname, os=os_name, ip=ip)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/eep')
def eep_page():
    app.logger.info("Accessing EEP page")
    security_manager.add_log('INFO', 'web', 'EEP page accessed', event_id='1002', process_id=os.getpid(), name='eep_page', host_id=request.remote_addr, destination=request.host)
    return render_template('eep.html')

@app.route('/api/eep/status')
def get_eep_status():
    try:
        status = security_manager.get_protection_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting EEP status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/eep/scan', methods=['POST'])
def scan_endpoint():
    try:
        result = security_manager.scan_endpoint()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error scanning endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/eep/update-definitions', methods=['POST'])
def update_definitions():
    try:
        result = security_manager.update_definitions()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error updating definitions: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/eep/settings', methods=['GET', 'POST'])
def eep_settings():
    if request.method == 'GET':
        # Return current settings
        return jsonify({
            'realtime_protection': True,
            'behavior_monitoring': True,
            'network_protection': True,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    else:
        try:
            settings = request.get_json()
            # Validate settings
            required_settings = ['realtime_protection', 'behavior_monitoring', 'network_protection']
            if not all(setting in settings for setting in required_settings):
                return jsonify({'status': 'Error', 'error': 'Missing required settings'}), 400
            
            # Update settings in security manager
            security_manager.update_eep_settings(settings)
            
            return jsonify({
                'status': 'Success',
                'message': 'Settings updated successfully',
                'settings': settings,
                'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        except Exception as e:
            app.logger.error(f"Error updating EEP settings: {str(e)}")
            return jsonify({'status': 'Error', 'error': str(e)}), 500

@app.route('/api/eep/endpoint')
def get_endpoint_details():
    try:
        details = security_manager.get_endpoint_details()
        return jsonify(details)
    except Exception as e:
        logger.error(f"Error getting endpoint details: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/metrics')
def get_metrics():
    try:
        # Get system information
        system_info = security_manager.system_info
        
        # Get CPU and memory usage
        cpu_data = security_manager.get_cpu_usage()
        memory_data = security_manager.get_memory_usage()
        
        # Get network activity
        network_data = security_manager.get_network_connections()
        
        # Get running processes with error handling
        try:
            processes = security_manager.get_running_processes()
            if not processes:
                processes = []  # Ensure we return an empty list if no processes found
        except Exception as e:
            logger.error(f"Error getting processes: {str(e)}")
            processes = []
        
        # Calculate threat level based on various factors
        threat_level = calculate_threat_level()
        
        # Get system status
        system_status = get_system_status()
        
        # Add new real-time metrics
        uptime = security_manager.get_uptime()
        disk = security_manager.get_disk_usage()
        current_time = security_manager.get_current_time()
        
        return jsonify({
            'system_info': system_info,
            'cpu': {
                'current': cpu_data['current'],
                'frequency': cpu_data['frequency'],
                'history': cpu_data['history']
            },
            'memory': {
                'current': memory_data['current'],
                'details': memory_data['details']
            },
            'network': {
                'connections': len(network_data['connections']),
                'interfaces': network_data['interfaces']
            },
            'processes': processes,
            'threat': threat_level,
            'status': system_status,
            'uptime': uptime,
            'disk': disk,
            'current_time': current_time
        })
    except Exception as e:
        logger.error(f"Error getting metrics: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/policies', methods=['GET'])
@cache_response(timeout=30)  # Cache for 30 seconds
def get_policies():
    try:
        policies = security_manager.get_security_policies()
        return jsonify(policies)
    except Exception as e:
        logger.error(f"Error getting policies: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/policies', methods=['POST'])
def add_policy():
    try:
        policy_data = request.json
        success = security_manager.add_security_policy(
            policy_data['type'],
            policy_data['config']
        )
        return jsonify({'success': success})
    except Exception as e:
        logger.error(f"Error adding policy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/policies/<policy_id>', methods=['DELETE'])
def delete_policy(policy_id):
    try:
        success = security_manager.delete_security_policy(policy_id)
        return jsonify({'success': success})
    except Exception as e:
        logger.error(f"Error deleting policy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@cache_response(timeout=10)  # Cache for 10 seconds
def calculate_threat_level():
    try:
        cpu_data = security_manager.get_cpu_usage()
        memory_data = security_manager.get_memory_usage()
        network_data = security_manager.get_network_connections()
        
        # Calculate threat level based on system metrics
        cpu_threat = 0
        if cpu_data['current'] > 90:
            cpu_threat = 3
        elif cpu_data['current'] > 70:
            cpu_threat = 2
        elif cpu_data['current'] > 50:
            cpu_threat = 1

        memory_threat = 0
        if memory_data['current'] > 90:
            memory_threat = 3
        elif memory_data['current'] > 70:
            memory_threat = 2
        elif memory_data['current'] > 50:
            memory_threat = 1

        network_threat = 0
        if len(network_data['connections']) > 100:
            network_threat = 3
        elif len(network_data['connections']) > 50:
            network_threat = 2
        elif len(network_data['connections']) > 20:
            network_threat = 1

        # Calculate overall threat level
        threat_level = max(cpu_threat, memory_threat, network_threat)
        
        return {
            'level': threat_level,
            'details': {
                'cpu': cpu_threat,
                'memory': memory_threat,
                'network': network_threat
            }
        }
    except Exception as e:
        logger.error(f"Error calculating threat level: {str(e)}")
        return {'level': 0, 'details': {'cpu': 0, 'memory': 0, 'network': 0}}

@cache_response(timeout=10)  # Cache for 10 seconds
def get_system_status():
    try:
        protection_status = security_manager.get_protection_status()
        return {
            'protection': protection_status['status'],
            'defender': protection_status['defender'],
            'firewall': protection_status['firewall'],
            'realtime': protection_status['realtime'],
            'last_updated': protection_status['last_updated']
        }
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        return {'status': 'Unknown', 'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

@app.route('/log')
def log_page():
    app.logger.info("Accessing Log page")
    security_manager.add_log('INFO', 'web', 'Log page accessed', event_id='1003', process_id=os.getpid(), name='log_page', host_id=request.remote_addr, destination=request.host)
    return render_template('log.html')

@app.route('/api/logs')
def get_logs():
    try:
        level = request.args.get('level', 'all')
        source = request.args.get('source', 'all')
        time_range = request.args.get('timeRange', '24h')

        # Get logs from security manager
        logs = security_manager.get_logs(level, source, time_range)
        return jsonify({'logs': logs})
    except Exception as e:
        app.logger.error(f"Error getting logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/export')
def export_logs():
    try:
        level = request.args.get('level', 'all')
        source = request.args.get('source', 'all')
        time_range = request.args.get('timeRange', '24h')

        # Get logs from security manager
        logs = security_manager.get_logs(level, source, time_range)
        
        # Create CSV content
        csv_content = "Timestamp,Level,Source,Message\n"
        for log in logs:
            csv_content += f"{log['timestamp']},{log['level']},{log['source']},{log['message']}\n"
        
        # Create response with CSV file
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=security_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return response
    except Exception as e:
        app.logger.error(f"Error exporting logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/soc-helper')
@login_required
def soc_helper():
    return render_template('soc_helper.html')

@app.route('/api/logs/realtime')
def get_realtime_logs():
    try:
        logs = security_manager.get_logs(level='all', source='all', time_range='1h')
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- 1. Threat Intelligence Integration ---
@app.route('/api/threat-intel/<ip>')
def threat_intel_lookup(ip):
    try:
        api_key = 'YOUR_ABUSEIPDB_API_KEY'  # Replace with your real key
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
        headers = {'Key': api_key, 'Accept': 'application/json'}
        response = requests.get(url, headers=headers)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- 2. Alerting & Notification System (scaffold) ---
@app.route('/api/alerts', methods=['GET', 'POST'])
def alerts():
    if request.method == 'POST':
        # Placeholder: Add alert rule
        return jsonify({'status': 'Alert rule added (placeholder)'}), 201
    else:
        # Placeholder: Get alerts
        return jsonify({'alerts': []})

# --- 3. UEBA (scaffold) ---
@app.route('/api/ueba')
def ueba():
    # Placeholder: Return user/entity behavior analytics
    return jsonify({'ueba': 'UEBA data (placeholder)'})

# --- 4. Incident Response Playbooks (scaffold) ---
@app.route('/api/ir-playbooks')
def ir_playbooks():
    # Placeholder: Return IR playbooks
    return jsonify({'playbooks': []})

# --- 5. Automated Log Enrichment (scaffold) ---
@app.route('/api/logs/enrich')
def enrich_logs():
    # Placeholder: Return enriched logs
    return jsonify({'logs': []})

# --- 6. Advanced Search & Filtering (scaffold) ---
@app.route('/api/logs/search')
def search_logs():
    # Placeholder: Return search results
    return jsonify({'results': []})

# --- 7. Custom Dashboards & Reporting (scaffold) ---
@app.route('/api/dashboards')
def dashboards():
    # Placeholder: Return dashboards
    return jsonify({'dashboards': []})

# --- 8. File Integrity Monitoring (scaffold) ---
@app.route('/api/file-integrity')
def file_integrity():
    # Placeholder: Return file integrity status
    return jsonify({'integrity': 'OK (placeholder)'})

# --- 9. EDR/AV/Firewall Integration (scaffold) ---
@app.route('/api/integrations')
def integrations():
    # Placeholder: Return integration status
    return jsonify({'integrations': []})

# --- 10. Case Management (scaffold) ---
@app.route('/api/cases')
def cases():
    # Placeholder: Return cases
    return jsonify({'cases': []})

# --- 11. MITRE ATT&CK Mapping (scaffold) ---
@app.route('/api/mitre')
def mitre():
    # Placeholder: Return MITRE mapping
    return jsonify({'mitre': []})

# --- 12. Anomaly Detection (scaffold) ---
@app.route('/api/anomalies')
def anomalies():
    # Placeholder: Return anomalies
    return jsonify({'anomalies': []})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Simple authentication logic (replace with your own as needed)
        if username == 'admin' and password == 'admin':
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/api/eep/apply-policy', methods=['POST'])
def apply_eep_policy():
    try:
        import subprocess
        import os
        policy = request.get_json()
        app.logger.info(f"Applying EPP policy: {policy}")
        blocked = []
        renamed = []
        debug_info = {}
        if 'browser_block' in policy:
            browser_map = {
                'chrome': {
                    'exe': 'chrome.exe',
                    'paths': [
                        r'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                    ]
                },
                'edge': {
                    'exe': 'msedge.exe',
                    'paths': [
                        r'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
                        r'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'
                    ]
                },
                'firefox': {
                    'exe': 'firefox.exe',
                    'paths': [
                        r'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
                        r'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe'
                    ]
                },
                'opera': {
                    'exe': 'opera.exe',
                    'paths': [
                        r'C:\\Program Files\\Opera\\launcher.exe',
                        r'C:\\Program Files (x86)\\Opera\\launcher.exe'
                    ]
                }
            }
            for browser in policy['browser_block']:
                binfo = browser_map.get(browser)
                if binfo:
                    exe = binfo['exe']
                    # 1. Kill the process
                    try:
                        result = subprocess.run([
                            'taskkill', '/F', '/IM', exe
                        ], capture_output=True, text=True)
                        debug_info[browser] = {
                            'returncode': result.returncode,
                            'stdout': result.stdout,
                            'stderr': result.stderr
                        }
                        if result.returncode == 0:
                            blocked.append(browser)
                    except Exception as e:
                        debug_info[browser] = {'error': str(e)}
                    # 2. Rename the executable in common locations
                    for path in binfo['paths']:
                        try:
                            if os.path.exists(path):
                                os.rename(path, path + '.blocked')
                                renamed.append(path)
                                if 'renamed' not in debug_info[browser]:
                                    debug_info[browser]['renamed'] = []
                                debug_info[browser]['renamed'].append(f"Renamed {path} to {path}.blocked")
                            else:
                                if 'rename_error' not in debug_info[browser]:
                                    debug_info[browser]['rename_error'] = []
                                debug_info[browser]['rename_error'].append(f"{path}: File does not exist")
                        except Exception as e:
                            if 'rename_error' not in debug_info[browser]:
                                debug_info[browser]['rename_error'] = []
                            debug_info[browser]['rename_error'].append(f"{path}: {str(e)}")
            app.logger.info(f"Blocked browsers: {blocked}")
            app.logger.info(f"Renamed executables: {renamed}")
            app.logger.info(f"Taskkill debug info: {debug_info}")
        return jsonify({'status': 'success', 'message': f'Policy applied. Blocked browsers: {blocked}. Renamed: {renamed}', 'policy': policy, 'debug': debug_info})
    except Exception as e:
        app.logger.error(f"Error applying EPP policy: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    try:
        logger.info("Initializing Security Manager...")
        security_manager.initialize()
        logger.info("Starting Flask app...")
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Error starting application: {str(e)}") 