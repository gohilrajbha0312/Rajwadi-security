import uuid
from datetime import datetime
import logging
import os
import json

class PlaybookManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.playbooks = []
        # Set the playbooks directory path
        self.playbooks_dir = r"C:\Users\gohil\OneDrive\Desktop\python\playbooks"
        # Create directory if it doesn't exist
        os.makedirs(self.playbooks_dir, exist_ok=True)
        self.initialize_default_playbooks()

    def initialize_default_playbooks(self):
        """Initialize default playbooks for common security scenarios"""
        self.playbooks = [
            {
                'id': str(uuid.uuid4()),
                'title': 'Ransomware Attack Response',
                'description': 'Comprehensive response plan for ransomware attacks',
                'category': 'ransomware',
                'tags': ['ransomware', 'malware', 'incident-response'],
                'steps': [
                    {
                        'description': 'Isolate affected systems from the network',
                        'status': 'pending'
                    },
                    {
                        'description': 'Identify the ransomware variant and encryption method',
                        'status': 'pending'
                    },
                    {
                        'description': 'Assess the scope of the infection',
                        'status': 'pending'
                    },
                    {
                        'description': 'Report the incident to relevant authorities',
                        'status': 'pending'
                    },
                    {
                        'description': 'Restore systems from clean backups',
                        'status': 'pending'
                    }
                ],
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            },
            {
                'id': str(uuid.uuid4()),
                'title': 'Advanced Persistent Threat (APT) Detection',
                'description': 'Proactive detection and response procedures for APT attacks',
                'category': 'apt',
                'tags': ['apt', 'threat-hunting', 'detection'],
                'steps': [
                    {
                        'description': 'Monitor network traffic for suspicious patterns',
                        'status': 'pending'
                    },
                    {
                        'description': 'Analyze system logs for unusual activities',
                        'status': 'pending'
                    },
                    {
                        'description': 'Investigate potential command and control communications',
                        'status': 'pending'
                    },
                    {
                        'description': 'Implement additional security controls',
                        'status': 'pending'
                    }
                ],
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            },
            {
                'id': str(uuid.uuid4()),
                'title': 'Data Breach Response',
                'description': 'Procedures for handling data breaches and information leaks',
                'category': 'data-breach',
                'tags': ['data-breach', 'privacy', 'incident-response'],
                'steps': [
                    {
                        'description': 'Identify the type and scope of compromised data',
                        'status': 'pending'
                    },
                    {
                        'description': 'Contain the breach and prevent further data loss',
                        'status': 'pending'
                    },
                    {
                        'description': 'Notify affected parties and regulatory bodies',
                        'status': 'pending'
                    },
                    {
                        'description': 'Implement remediation measures',
                        'status': 'pending'
                    }
                ],
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
        ]
        self.logger.info("Default playbooks initialized successfully")

    def get_playbooks(self, search_query='', category='all'):
        """Get all playbooks with optional search and category filter"""
        try:
            filtered_playbooks = self.playbooks
            
            # Apply search filter
            if search_query:
                search_query = search_query.lower()
                filtered_playbooks = [
                    p for p in filtered_playbooks
                    if search_query in p['title'].lower() or
                    search_query in p['description'].lower() or
                    any(search_query in tag.lower() for tag in p['tags'])
                ]
            
            # Apply category filter
            if category != 'all':
                filtered_playbooks = [
                    p for p in filtered_playbooks
                    if p['category'] == category
                ]
            
            return filtered_playbooks
        except Exception as e:
            self.logger.error(f"Error getting playbooks: {str(e)}")
            return []

    def save_playbook_to_file(self, playbook):
        """Save a playbook to a JSON file"""
        try:
            filename = f"playbook_{playbook['id']}.json"
            filepath = os.path.join(self.playbooks_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(playbook, f, indent=4)
            
            self.logger.info(f"Playbook saved to file: {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving playbook to file: {str(e)}")
            return False

    def add_playbook(self, playbook_data):
        """Add a new playbook"""
        try:
            # Generate a unique ID
            playbook_id = str(uuid.uuid4())
            
            # Create new playbook with ID
            new_playbook = {
                'id': playbook_id,
                'title': playbook_data['title'],
                'description': playbook_data['description'],
                'category': playbook_data['category'],
                'tags': playbook_data['tags'],
                'steps': playbook_data['steps'],
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            # Add to playbooks list
            self.playbooks.append(new_playbook)
            
            # Save to file
            self.save_playbook_to_file(new_playbook)
            
            # Log the addition
            self.logger.info(f"New playbook added: {new_playbook['title']}")
            
            return new_playbook
        except Exception as e:
            self.logger.error(f"Error adding playbook: {str(e)}")
            raise

    def update_playbook(self, playbook_id, updated_data):
        """Update an existing playbook"""
        try:
            # Find the playbook
            playbook = next((p for p in self.playbooks if p['id'] == playbook_id), None)
            if not playbook:
                raise ValueError(f"Playbook with ID {playbook_id} not found")
            
            # Update fields
            playbook.update({
                'title': updated_data.get('title', playbook['title']),
                'description': updated_data.get('description', playbook['description']),
                'category': updated_data.get('category', playbook['category']),
                'tags': updated_data.get('tags', playbook['tags']),
                'steps': updated_data.get('steps', playbook['steps']),
                'updated_at': datetime.now().isoformat()
            })
            
            # Save to file
            self.save_playbook_to_file(playbook)
            
            # Log the update
            self.logger.info(f"Playbook updated: {playbook['title']}")
            
            return playbook
        except Exception as e:
            self.logger.error(f"Error updating playbook: {str(e)}")
            raise

    def delete_playbook(self, playbook_id):
        """Delete a playbook"""
        try:
            # Find and remove the playbook
            playbook = next((p for p in self.playbooks if p['id'] == playbook_id), None)
            if not playbook:
                raise ValueError(f"Playbook with ID {playbook_id} not found")
            
            # Remove from list
            self.playbooks = [p for p in self.playbooks if p['id'] != playbook_id]
            
            # Delete the file
            filename = f"playbook_{playbook_id}.json"
            filepath = os.path.join(self.playbooks_dir, filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            
            # Log the deletion
            self.logger.info(f"Playbook deleted: {playbook['title']}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error deleting playbook: {str(e)}")
            raise

    def get_playbook_by_id(self, playbook_id):
        """Get a specific playbook by ID"""
        try:
            playbook = next((p for p in self.playbooks if p['id'] == playbook_id), None)
            if not playbook:
                raise ValueError(f"Playbook with ID {playbook_id} not found")
            return playbook
        except Exception as e:
            self.logger.error(f"Error getting playbook: {str(e)}")
            raise

    def delete_all_playbooks(self):
        """Delete all playbooks"""
        try:
            # Delete all files in the playbooks directory
            if os.path.exists(self.playbooks_dir):
                for filename in os.listdir(self.playbooks_dir):
                    if filename.startswith('playbook_') and filename.endswith('.json'):
                        file_path = os.path.join(self.playbooks_dir, filename)
                        try:
                            os.remove(file_path)
                            self.logger.info(f"Deleted playbook file: {filename}")
                        except Exception as e:
                            self.logger.error(f"Error deleting file {filename}: {str(e)}")
            
            # Clear the playbooks list
            self.playbooks = []
            self.logger.info("All playbooks deleted successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting all playbooks: {str(e)}")
            return False 