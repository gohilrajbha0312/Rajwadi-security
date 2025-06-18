from flask import Flask, render_template, jsonify, request, make_response
from security_manager import SecurityManager
import logging
from datetime import datetime
import random
from playbook import PlaybookManager
import os
import json
from functools import wraps
import time
import subprocess

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Set the playbooks directory path
playbooks_dir = r"C:\Users\gohil\OneDrive\Desktop\python\playbooks"

# Initialize managers
security_manager = SecurityManager()
playbook_manager = PlaybookManager()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

@app.route('/')
def index():
    app.logger.info("Accessing Dashboard")
    return render_template('index.html')

@app.route('/eep')
def eep_page():
    app.logger.info("Accessing EEP page")
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
@cache_response(timeout=5)  # Cache for 5 seconds
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
            'status': system_status
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

@app.route('/playbook')
def playbook_page():
    try:
        # Ensure playbooks directory exists
        if not os.path.exists(playbooks_dir):
            os.makedirs(playbooks_dir)
            logger.info(f"Created playbooks directory: {playbooks_dir}")
        
        # Open VS Code in the playbooks directory
        if os.name == 'nt':  # Windows
            vscode_path = r'C:\Users\gohil\AppData\Local\Programs\Microsoft VS Code\Code.exe'
            if os.path.exists(vscode_path):
                subprocess.Popen([vscode_path, playbooks_dir])
                logger.info(f"Opened VS Code in directory: {playbooks_dir}")
            else:
                logger.error("VS Code not found at the expected path")
        
        app.logger.info("Accessing Playbook page")
        return render_template('playbook.html')
    except Exception as e:
        logger.error(f"Error opening playbooks directory: {str(e)}")
        return render_template('playbook.html')

@app.route('/api/playbooks', methods=['GET'])
def get_playbooks():
    """Get all playbooks"""
    try:
        playbooks = playbook_manager.get_playbooks()
        return jsonify(playbooks)
    except Exception as e:
        logger.error(f"Error getting playbooks: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/playbooks', methods=['POST'])
def create_playbook():
    try:
        playbook_data = request.json
        
        # Validate required fields
        required_fields = ['title', 'description', 'category', 'tags', 'steps']
        if not all(field in playbook_data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate data types
        if not isinstance(playbook_data['tags'], list):
            return jsonify({'error': 'Tags must be a list'}), 400
        if not isinstance(playbook_data['steps'], list):
            return jsonify({'error': 'Steps must be a list'}), 400
        
        # Ensure playbooks directory exists
        if not os.path.exists(playbooks_dir):
            os.makedirs(playbooks_dir)
            logger.info(f"Created playbooks directory: {playbooks_dir}")
        
        # Add playbook to manager
        new_playbook = playbook_manager.add_playbook(playbook_data)
        
        # Save playbook to file
        try:
            filename = f"playbook_{new_playbook['id']}.json"
            filepath = os.path.join(playbooks_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(new_playbook, f, indent=4)
            
            logger.info(f"Saved playbook to file: {filepath}")
            
            # Open VS Code in the playbooks directory
            if os.name == 'nt':  # Windows
                vscode_path = r'C:\Users\gohil\AppData\Local\Programs\Microsoft VS Code\Code.exe'
                if os.path.exists(vscode_path):
                    subprocess.Popen([vscode_path, playbooks_dir])
                    logger.info(f"Opened VS Code in directory: {playbooks_dir}")
        
        except Exception as e:
            logger.error(f"Error saving playbook file: {str(e)}")
            return jsonify({
                'status': 'Error',
                'message': f'Playbook created but failed to save file: {str(e)}'
            }), 500
        
        return jsonify({
            'status': 'success',
            'message': 'Playbook created successfully',
            'playbook': new_playbook,
            'file_path': filepath
        })
    except Exception as e:
        logger.error(f"Error creating playbook: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks/<playbook_id>', methods=['DELETE', 'PUT'])
def manage_playbook(playbook_id):
    if request.method == 'DELETE':
        try:
            result = playbook_manager.delete_playbook(playbook_id)
            if result:
                return jsonify({
                    'status': 'Success',
                    'message': 'Playbook deleted successfully'
                })
            else:
                return jsonify({
                    'status': 'Error',
                    'message': 'Failed to delete playbook'
                }), 500
        except Exception as e:
            app.logger.error(f"Error deleting playbook: {str(e)}")
            return jsonify({
                'status': 'Error',
                'error': str(e)
            }), 500
    else:  # PUT request
        try:
            updated_playbook = request.get_json()
            result = playbook_manager.update_playbook(playbook_id, updated_playbook)
            return jsonify({
                'status': 'Success',
                'message': 'Playbook updated successfully',
                'playbook': result
            })
        except Exception as e:
            app.logger.error(f"Error updating playbook: {str(e)}")
            return jsonify({
                'status': 'Error',
                'error': str(e)
            }), 500

@app.route('/api/playbooks/delete-all', methods=['DELETE'])
def delete_all_playbooks():
    try:
        result = playbook_manager.delete_all_playbooks()
        if result:
            return jsonify({
                'status': 'Success',
                'message': 'All playbooks deleted successfully'
            })
        else:
            return jsonify({
                'status': 'Error',
                'message': 'Failed to delete all playbooks'
            }), 500
    except Exception as e:
        logger.error(f"Error deleting all playbooks: {str(e)}")
        return jsonify({
            'status': 'Error',
            'error': str(e)
        }), 500

@app.route('/api/open-playbooks-directory', methods=['POST'])
def open_playbooks_directory():
    try:
        # Ensure the directory exists
        if not os.path.exists(playbooks_dir):
            os.makedirs(playbooks_dir)
            logger.info(f"Created directory: {playbooks_dir}")
        
        # Open VS Code in the playbooks directory
        if os.name == 'nt':  # Windows
            vscode_path = r'C:\Users\gohil\AppData\Local\Programs\Microsoft VS Code\Code.exe'
            if os.path.exists(vscode_path):
                subprocess.Popen([vscode_path, playbooks_dir])
                logger.info(f"Opened VS Code in directory: {playbooks_dir}")
                return jsonify({
                    'status': 'Success',
                    'message': 'Opened playbooks directory in VS Code'
                })
            else:
                raise Exception("VS Code not found at the expected path")
        else:  # Linux/Mac
            subprocess.Popen(['code', playbooks_dir])
            return jsonify({
                'status': 'Success',
                'message': 'Opened playbooks directory in VS Code'
            })
    except Exception as e:
        logger.error(f"Error opening playbooks directory: {str(e)}")
        return jsonify({
            'status': 'Error',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    try:
        logger.info("Initializing Security Manager...")
        security_manager.initialize()
        logger.info("Starting Flask app...")
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Error starting application: {str(e)}") 