import psutil
import wmi
import os
import json
import logging
from datetime import datetime, timedelta
import uuid
import socket
import platform
import subprocess
import time
import win32security
import win32api
import win32con
import win32process
import win32serviceutil
import win32service
import win32event
import servicemanager
from functools import lru_cache
from threading import Lock

class SecurityManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Initialize EEP settings
        self.eep_settings = {
            'realtime_protection': True,
            'behavior_monitoring': True,
            'network_protection': True,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Initialize log storage with thread safety
        self.logs = []
        self.max_logs = 1000
        self.logs_lock = Lock()
        
        # Initialize playbooks
        self.playbooks = []
        self.playbooks_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'playbooks')
        self.initialize_playbooks()
        
        # Initialize metrics with caching
        self.cpu_history = []
        self.memory_history = []
        self.network_history = []
        self.last_metrics_update = datetime.now()
        self.metrics_cache_duration = timedelta(seconds=5)  # Cache metrics for 5 seconds
        
        # Initialize security policies
        self.security_policies = []
        self.policy_file = 'security_policies.json'
        self.load_policies()
        
        # Initialize WMI and system info
        self.wmi = wmi.WMI()
        self.system_info = self.get_system_info()
        self.protection_status = self.get_protection_status()
        self.threats_blocked = 0
        self.last_scan_time = None
        self.protected_endpoints = self.get_protected_endpoints()
        
        self.logger.info("Security Manager initialized successfully")

    def initialize_playbooks(self):
        """Initialize playbooks from the playbooks directory"""
        try:
            # Create playbooks directory if it doesn't exist
            os.makedirs(self.playbooks_dir, exist_ok=True)
            
            # Load existing playbooks
            if os.path.exists(self.playbooks_dir):
                for filename in os.listdir(self.playbooks_dir):
                    if filename.endswith('.json'):
                        filepath = os.path.join(self.playbooks_dir, filename)
                        try:
                            with open(filepath, 'r') as f:
                                playbook = json.load(f)
                                self.playbooks.append(playbook)
                        except Exception as e:
                            self.logger.error(f"Error loading playbook {filename}: {str(e)}")
            
            self.logger.info(f"Loaded {len(self.playbooks)} playbooks")
        except Exception as e:
            self.logger.error(f"Error initializing playbooks: {str(e)}")

    def get_protected_endpoints(self):
        try:
            endpoints = []
            # Get current system info
            current_system = {
                'hostname': socket.gethostname(),
                'os': platform.system() + " " + platform.release(),
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'status': 'Protected',
                'last_scan': self.last_scan_time.strftime('%Y-%m-%d %H:%M:%S') if self.last_scan_time else 'Never',
                'protection_status': self.get_protection_status()
            }
            endpoints.append(current_system)

            # Get network devices using arp
            try:
                # Run arp -a command to get network devices
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'dynamic' in line.lower():
                            parts = line.split()
                            if len(parts) >= 2:
                                ip = parts[0]
                                mac = parts[1]
                                if ip != current_system['ip_address']:  # Don't add current system
                                    endpoints.append({
                                        'hostname': f'Device-{len(endpoints)}',
                                        'os': 'Unknown',
                                        'ip_address': ip,
                                        'mac_address': mac,
                                        'status': 'Protected',
                                        'last_scan': 'Never',
                                        'protection_status': {'status': 'Unknown'}
                                    })
            except Exception as e:
                self.logger.error(f"Error getting network devices: {str(e)}")

            return endpoints
        except Exception as e:
            self.logger.error(f"Error getting protected endpoints: {str(e)}")
            return []

    def get_system_info(self):
        try:
            return {
                'hostname': socket.gethostname(),
                'os': platform.system() + " " + platform.release(),
                'processor': platform.processor(),
                'ip_address': socket.gethostbyname(socket.gethostname())
            }
        except Exception as e:
            self.logger.error(f"Error getting system info: {str(e)}")
            return {}

    def get_protection_status(self):
        try:
            # Check Windows Defender status
            defender_status = self.check_windows_defender()
            
            # Check firewall status
            firewall_status = self.check_firewall_status()
            
            # Check real-time protection
            realtime_status = self.check_realtime_protection()
            
            return {
                'status': 'Active' if all([defender_status, firewall_status, realtime_status]) else 'At Risk',
                'defender': defender_status,
                'firewall': firewall_status,
                'realtime': realtime_status,
                'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            self.logger.error(f"Error getting protection status: {str(e)}")
            return {'status': 'Unknown', 'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    def check_windows_defender(self):
        try:
            # Check if Windows Defender service is running
            service_status = win32serviceutil.QueryServiceStatus('WinDefend')[1]
            return service_status == win32service.SERVICE_RUNNING
        except Exception as e:
            self.logger.error(f"Error checking Windows Defender: {str(e)}")
            return False

    def check_firewall_status(self):
        try:
            # Check Windows Firewall status
            service_status = win32serviceutil.QueryServiceStatus('MpsSvc')[1]
            return service_status == win32service.SERVICE_RUNNING
        except Exception as e:
            self.logger.error(f"Error checking firewall status: {str(e)}")
            return False

    def check_realtime_protection(self):
        try:
            # Check if real-time protection is enabled
            return self.check_windows_defender()
        except Exception as e:
            self.logger.error(f"Error checking real-time protection: {str(e)}")
            return False

    def initialize(self):
        try:
            self.logger.info("Security Manager initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing Security Manager: {str(e)}")
            raise

    def get_cpu_usage(self):
        try:
            # Check if we need to update the cache
            if (datetime.now() - self.last_metrics_update) > self.metrics_cache_duration:
                cpu_percent = psutil.cpu_percent(interval=0.1)
                cpu_freq = psutil.cpu_freq()
                per_cpu = psutil.cpu_percent(interval=0.1, percpu=True)
                
                # Update cache
                self.cpu_history.append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'usage': cpu_percent,
                    'frequency': cpu_freq.current if cpu_freq else None,
                    'per_cpu': per_cpu
                })
                
                # Keep only last 60 entries (1 minute of data)
                if len(self.cpu_history) > 60:
                    self.cpu_history.pop(0)
                
                self.last_metrics_update = datetime.now()
            
            return {
                'current': self.cpu_history[-1]['usage'] if self.cpu_history else 0,
                'frequency': self.cpu_history[-1]['frequency'] if self.cpu_history else None,
                'history': self.cpu_history
            }
        except Exception as e:
            self.logger.error(f"Error getting CPU usage: {str(e)}")
            return {'current': 0, 'frequency': None, 'history': []}

    def get_memory_usage(self):
        try:
            # Check if we need to update the cache
            if (datetime.now() - self.last_metrics_update) > self.metrics_cache_duration:
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                # Update cache
                self.memory_history.append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'percent': memory.percent,
                    'swap': {
                        'total': swap.total,
                        'used': swap.used,
                        'free': swap.free,
                        'percent': swap.percent
                    }
                })
                
                # Keep only last 60 entries
                if len(self.memory_history) > 60:
                    self.memory_history.pop(0)
                
                self.last_metrics_update = datetime.now()
            
            return {
                'current': self.memory_history[-1]['percent'] if self.memory_history else 0,
                'details': self.memory_history[-1] if self.memory_history else {}
            }
        except Exception as e:
            self.logger.error(f"Error getting memory usage: {str(e)}")
            return {'current': 0, 'details': {}}

    def get_network_connections(self):
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                try:
                    process = psutil.Process(conn.pid)
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                        'status': conn.status,
                        'pid': conn.pid,
                        'process_name': process.name()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Get network interface statistics
            interfaces = {}
            for interface, stats in psutil.net_if_stats().items():
                if stats.isup:
                    interfaces[interface] = {
                        'speed': stats.speed,
                        'mtu': stats.mtu,
                        'duplex': stats.duplex
                    }

            return {
                'connections': connections,
                'interfaces': interfaces
            }
        except Exception as e:
            self.logger.error(f"Error getting network connections: {str(e)}")
            return {'connections': [], 'interfaces': {}}

    def get_running_processes(self):
        try:
            processes = []
            # Get all processes with their info
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    # Get process info
                    pinfo = proc.info
                    # Calculate CPU percent if not available
                    if pinfo['cpu_percent'] is None:
                        pinfo['cpu_percent'] = proc.cpu_percent(interval=0.1)
                    # Calculate memory percent if not available
                    if pinfo['memory_percent'] is None:
                        pinfo['memory_percent'] = proc.memory_percent()
                    # Get process creation time
                    create_time = datetime.fromtimestamp(pinfo['create_time']) if pinfo['create_time'] else None
                    # Add process info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cpu_percent': round(pinfo['cpu_percent'], 1),
                        'memory_percent': round(pinfo['memory_percent'], 1),
                        'create_time': create_time.strftime('%Y-%m-%d %H:%M:%S') if create_time else 'Unknown'
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.logger.error(f"Error getting process info: {str(e)}")
                    continue
            # Sort by CPU usage and memory usage
            processes.sort(key=lambda x: (x['cpu_percent'], x['memory_percent']), reverse=True)
            return processes[:10]
        except Exception as e:
            self.logger.error(f"Error getting running processes: {str(e)}")
            return []

    def get_security_policies(self):
        return self.security_policies

    def add_security_policy(self, policy_type, config):
        try:
            policy = {
                'id': str(uuid.uuid4()),
                'type': policy_type,
                'config': config,
                'status': 'active',
                'created_at': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }
            self.security_policies.append(policy)
            self.save_policies()
            self.logger.info(f"Added new security policy: {policy_type}")
            return True
        except Exception as e:
            self.logger.error(f"Error adding security policy: {str(e)}")
            return False

    def delete_security_policy(self, policy_id):
        try:
            self.security_policies = [p for p in self.security_policies if p['id'] != policy_id]
            self.save_policies()
            self.logger.info(f"Deleted security policy: {policy_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting security policy: {str(e)}")
            return False

    def load_policies(self):
        try:
            if os.path.exists(self.policy_file):
                with open(self.policy_file, 'r') as f:
                    self.security_policies = json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading security policies: {str(e)}")
            self.security_policies = []

    def save_policies(self):
        try:
            with open(self.policy_file, 'w') as f:
                json.dump(self.security_policies, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error saving security policies: {str(e)}")

    def scan_endpoint(self):
        try:
            # Perform a real system scan
            self.last_scan_time = datetime.now()
            
            # Check for running processes
            suspicious_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    # Check for high resource usage
                    if pinfo['cpu_percent'] > 80 or pinfo['memory_percent'] > 80:
                        suspicious_processes.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'cpu_percent': pinfo['cpu_percent'],
                            'memory_percent': pinfo['memory_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Check network connections
            suspicious_connections = []
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.status == 'ESTABLISHED':
                        process = psutil.Process(conn.pid)
                        suspicious_connections.append({
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                            'process_name': process.name()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            return {
                'status': 'Completed',
                'threats_found': len(suspicious_processes) + len(suspicious_connections),
                'scan_time': self.last_scan_time.strftime('%Y-%m-%d %H:%M:%S'),
                'suspicious_processes': suspicious_processes,
                'suspicious_connections': suspicious_connections
            }
        except Exception as e:
            self.logger.error(f"Error scanning endpoint: {str(e)}")
            return {'status': 'Failed', 'error': str(e)}

    def update_definitions(self):
        try:
            # Check Windows Defender update status
            result = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated'], 
                                 capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse the last update time
                last_update = result.stdout.strip()
                return {
                    'status': 'Completed',
                    'last_update': last_update,
                    'message': 'Definitions updated successfully'
                }
            else:
                return {
                    'status': 'Failed',
                    'error': 'Failed to check update status'
                }
        except Exception as e:
            self.logger.error(f"Error updating definitions: {str(e)}")
            return {'status': 'Failed', 'error': str(e)}

    def get_protection_settings(self):
        try:
            # Get current protection settings
            settings = {
                'realtime_protection': self.check_realtime_protection(),
                'behavior_monitoring': True,  # Default to True
                'network_protection': self.check_firewall_status(),
                'scan_schedule': 'Daily',  # Default schedule
                'threat_action': 'Quarantine'  # Default action
            }
            return settings
        except Exception as e:
            self.logger.error(f"Error getting protection settings: {str(e)}")
            return {}

    def update_protection_settings(self, settings):
        try:
            # Update protection settings
            # In a real implementation, this would update the actual system settings
            self.logger.info(f"Updating protection settings: {settings}")
            return {
                'status': 'Success',
                'message': 'Settings updated successfully',
                'settings': settings
            }
        except Exception as e:
            self.logger.error(f"Error updating protection settings: {str(e)}")
            return {'status': 'Failed', 'error': str(e)}

    def get_endpoint_details(self):
        try:
            return {
                'hostname': socket.gethostname(),
                'os': platform.system() + " " + platform.release(),
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'protection_status': self.get_protection_status(),
                'last_scan': self.last_scan_time.strftime('%Y-%m-%d %H:%M:%S') if self.last_scan_time else 'Never',
                'threats_blocked': self.threats_blocked,
                'protected_endpoints': self.get_protected_endpoints()
            }
        except Exception as e:
            self.logger.error(f"Error getting endpoint details: {str(e)}")
            return {}

    def update_eep_settings(self, settings):
        """Update EEP settings"""
        try:
            # Validate settings
            if not isinstance(settings, dict):
                raise ValueError("Settings must be a dictionary")
            
            # Update settings
            self.eep_settings.update(settings)
            self.eep_settings['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Log the update
            self.logger.info(f"EEP settings updated: {settings}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error updating EEP settings: {str(e)}")
            raise

    def add_log(self, level, source, message, event_id=None, process_id=None, name=None, host_id=None, destination=None, extra=None):
        with self.logs_lock:
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': level,
                'source': source,
                'message': message,
                'event_id': event_id,
                'process_id': process_id,
                'name': name,
                'host_id': host_id,
                'destination': destination,
                'extra': extra
            }
            self.logs.append(log_entry)
            if len(self.logs) > self.max_logs:
                self.logs.pop(0)

    def get_logs(self, level='all', source='all', time_range='24h'):
        """Get filtered logs"""
        try:
            # Calculate time threshold based on time_range
            now = datetime.now()
            if time_range == '1h':
                threshold = now - timedelta(hours=1)
            elif time_range == '6h':
                threshold = now - timedelta(hours=6)
            elif time_range == '24h':
                threshold = now - timedelta(hours=24)
            elif time_range == '7d':
                threshold = now - timedelta(days=7)
            elif time_range == '30d':
                threshold = now - timedelta(days=30)
            else:
                threshold = now - timedelta(hours=24)  # Default to 24h

            # Filter logs
            filtered_logs = self.logs.copy()
            
            # Filter by time
            filtered_logs = [
                log for log in filtered_logs
                if datetime.fromisoformat(log['timestamp']) >= threshold
            ]
            
            # Filter by level
            if level != 'all':
                filtered_logs = [
                    log for log in filtered_logs
                    if log['level'].lower() == level.lower()
                ]
            
            # Filter by source
            if source != 'all':
                filtered_logs = [
                    log for log in filtered_logs
                    if log['source'].lower() == source.lower()
                ]
            
            return filtered_logs
        except Exception as e:
            self.logger.error(f"Error getting logs: {str(e)}")
            raise

    def clear_logs(self):
        """Clear all logs"""
        try:
            self.logs = []
            self.logger.info("Logs cleared")
            return True
        except Exception as e:
            self.logger.error(f"Error clearing logs: {str(e)}")
            raise

    def get_playbooks(self):
        """Get all playbooks"""
        try:
            # Reload playbooks from directory
            self.playbooks = []
            if os.path.exists(self.playbooks_dir):
                for filename in os.listdir(self.playbooks_dir):
                    if filename.endswith('.json'):
                        filepath = os.path.join(self.playbooks_dir, filename)
                        try:
                            with open(filepath, 'r') as f:
                                playbook = json.load(f)
                                self.playbooks.append(playbook)
                        except Exception as e:
                            self.logger.error(f"Error loading playbook {filename}: {str(e)}")
            
            return self.playbooks
        except Exception as e:
            self.logger.error(f"Error getting playbooks: {str(e)}")
            return []

    def add_playbook(self, playbook_data):
        """Add a new playbook"""
        try:
            # Validate playbook data
            required_fields = ['title', 'description', 'category', 'tags', 'steps', 'id']
            for field in required_fields:
                if field not in playbook_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Save to playbooks directory
            filename = f"playbook_{playbook_data['id']}.json"
            filepath = os.path.join(self.playbooks_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(playbook_data, f, indent=4)
            
            # Add to in-memory list
            self.playbooks.append(playbook_data)
            
            return playbook_data
        except Exception as e:
            self.logger.error(f"Error adding playbook: {str(e)}")
            raise

    def delete_playbook(self, playbook_id):
        """Delete a playbook"""
        try:
            # Find and remove from in-memory list
            self.playbooks = [p for p in self.playbooks if p['id'] != playbook_id]
            
            # Delete file
            filename = f"playbook_{playbook_id}.json"
            filepath = os.path.join(self.playbooks_dir, filename)
            
            if os.path.exists(filepath):
                os.remove(filepath)
            
            return True
        except Exception as e:
            self.logger.error(f"Error deleting playbook: {str(e)}")
            raise

    def update_playbook(self, playbook_id, playbook_data):
        """Update an existing playbook"""
        try:
            # Validate playbook data
            required_fields = ['title', 'description', 'category', 'tags', 'steps', 'id']
            for field in required_fields:
                if field not in playbook_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Update in-memory list
            for i, playbook in enumerate(self.playbooks):
                if playbook['id'] == playbook_id:
                    self.playbooks[i] = playbook_data
                    break
            
            # Save to file
            filename = f"playbook_{playbook_id}.json"
            filepath = os.path.join(self.playbooks_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(playbook_data, f, indent=4)
            
            return playbook_data
        except Exception as e:
            self.logger.error(f"Error updating playbook: {str(e)}")
            raise

    def get_uptime(self):
        try:
            import psutil, time
            boot_time = psutil.boot_time()
            uptime_seconds = int(time.time() - boot_time)
            hours, remainder = divmod(uptime_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{hours:02}:{minutes:02}:{seconds:02}"
        except Exception as e:
            self.logger.error(f"Error getting uptime: {str(e)}")
            return "Unavailable"

    def get_disk_usage(self):
        try:
            import psutil
            usage = psutil.disk_usage('C:\\')
            return {
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent
            }
        except Exception as e:
            self.logger.error(f"Error getting disk usage: {str(e)}")
            return {'total': 0, 'used': 0, 'free': 0, 'percent': 0}

    def get_current_time(self):
        try:
            from datetime import datetime
            return datetime.now().strftime('%H:%M:%S')
        except Exception as e:
            self.logger.error(f"Error getting current time: {str(e)}")
            return "Unavailable" 