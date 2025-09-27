import json
import sqlite3
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify
from collections import deque
import signal
import sys
import logging

app = Flask(__name__)


DATABASE_FILE = 'logs.db' 
LOG_FILE = 'cmd.log'
ALERT_THRESHOLD_SUSPICIOUS = 5 
ALERT_WINDOW_MINUTES = 10 


recent_commands = deque(maxlen=1000) 
db_lock = threading.Lock()


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class CommandLogDatabase:
    def __init__(self, db_file):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database with required tables"""
        with sqlite3.connect(self.db_file) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT,
                    pid INTEGER,
                    uid INTEGER,
                    gid INTEGER,
                    tty TEXT,
                    cwd TEXT,
                    command TEXT NOT NULL,
                    args TEXT,
                    suspicious BOOLEAN,
                    event_type TEXT,
                    source TEXT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    hostname TEXT,
                    description TEXT,
                    severity TEXT,
                    command_count INTEGER,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON commands(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_hostname ON commands(hostname)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_suspicious ON commands(suspicious)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_command ON commands(command)')
            
        logger.info("Database initialized successfully")
    
    def insert_command(self, data):
        """Insert a command log entry into the database"""
        with db_lock:
            try:
                with sqlite3.connect(self.db_file) as conn:
                    conn.execute('''
                        INSERT INTO commands 
                        (timestamp, hostname, pid, uid, gid, tty, cwd, command, args, 
                         suspicious, event_type, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        data.get('timestamp'),
                        data.get('hostname'),
                        data.get('pid'),
                        data.get('uid'),
                        data.get('gid'),
                        data.get('tty'),
                        data.get('cwd'),
                        data.get('command'),
                        data.get('args'),
                        data.get('suspicious', False),
                        data.get('event_type'),
                        data.get('source')
                    ))
                return True
            except Exception as e:
                logger.error(f"Database insert failed: {e}")
                return False
    
    def get_recent_suspicious(self, hostname, minutes=10):
        """Get recent suspicious commands from a specific host"""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.execute('''
                SELECT COUNT(*) FROM commands 
                WHERE hostname = ? AND suspicious = 1 
                AND datetime(received_at) > datetime('now', '-{} minutes')
            '''.format(minutes), (hostname,))
            return cursor.fetchone()[0]
    
    def create_alert(self, alert_type, hostname, description, severity, command_count):
        """Create a new alert"""
        with sqlite3.connect(self.db_file) as conn:
            conn.execute('''
                INSERT INTO alerts (alert_type, hostname, description, severity, command_count, 
                                  first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (alert_type, hostname, description, severity, command_count))


db = CommandLogDatabase(DATABASE_FILE)

def analyze_command(data):
    """Analyze command for suspicious patterns and generate alerts"""
    hostname = data.get('hostname', 'unknown')
    command = data.get('command', '')
    args = data.get('args', '')
    suspicious = data.get('suspicious', False)
    alerts = []
    full_command = f"{command} {args}".lower()
    
    if any(tool in full_command for tool in ['nmap', 'masscan', 'zmap', 'unicornscan']):
        alerts.append({
            'type': 'network_reconnaissance',
            'description': f'Network reconnaissance tool detected: {command}',
            'severity': 'HIGH'
        })

    if any(pattern in full_command for pattern in [
        'nc -l', 'netcat -l', '/bin/bash -i', '/bin/sh -i',
        'python -c import socket', 'perl -e', 'ruby -rsocket'
    ]):
        alerts.append({
            'type': 'reverse_shell',
            'description': f'Potential reverse shell detected: {command}',
            'severity': 'CRITICAL'
        })

    if any(pattern in full_command for pattern in [
        'curl -X POST', 'wget --post', 'nc ', 'scp ', 'rsync ',
        'tar -c', 'zip -r', 'base64 -w0'
    ]):
        alerts.append({
            'type': 'data_exfiltration',
            'description': f'Potential data exfiltration detected: {command}',
            'severity': 'HIGH'
        })

    if any(pattern in full_command for pattern in [
        'sudo su', 'su -', 'sudo -s', 'sudo bash',
        'chmod +s', 'chmod 4755', 'setuid'
    ]):
        alerts.append({
            'type': 'privilege_escalation',
            'description': f'Privilege escalation attempt: {command}',
            'severity': 'HIGH'
        })

    if any(pattern in full_command for pattern in [
        'crontab -e', 'crontab -l', 'systemctl enable',
        '~/.bashrc', '~/.profile', '/etc/rc.local',
        'chkconfig', 'update-rc.d'
    ]):
        alerts.append({
            'type': 'persistence',
            'description': f'Persistence mechanism detected: {command}',
            'severity': 'MEDIUM'
        })

    if any(pattern in full_command for pattern in [
        'ps aux', 'ps -ef', 'netstat -', 'ss -',
        'lsof', 'who', 'w ', 'id', 'groups'
    ]):
        alerts.append({
            'type': 'reconnaissance',
            'description': f'System reconnaissance: {command}',
            'severity': 'LOW'
        })

    for alert in alerts:
        try:
            db.create_alert(
                alert['type'],
                hostname,
                alert['description'],
                alert['severity'],
                1
            )
            logger.warning(f"ALERT [{alert['severity']}]: {alert['description']} on {hostname}")
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
    
    return alerts

def check_suspicious_threshold(hostname):
    """Check if suspicious command threshold is exceeded"""
    count = db.get_recent_suspicious(hostname, ALERT_WINDOW_MINUTES)
    if count >= ALERT_THRESHOLD_SUSPICIOUS:
        try:
            db.create_alert(
                'suspicious_threshold',
                hostname,
                f'Exceeded suspicious command threshold: {count} commands in {ALERT_WINDOW_MINUTES} minutes',
                'CRITICAL',
                count
            )
            logger.critical(f"THRESHOLD ALERT: {count} suspicious commands from {hostname}")
        except Exception as e:
            logger.error(f"Failed to create threshold alert: {e}")

@app.route('/api/commands', methods=['POST'])
def receive_commands():
    """Receive command logs from kernel module"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        if isinstance(data, dict):
            commands = [data]
        elif isinstance(data, list):
            commands = data
        else:
            return jsonify({'error': 'Invalid data format'}), 400
        
        processed = 0
        alerts_generated = 0
        
        for cmd_data in commands:
            if not cmd_data.get('command'):
                logger.warning("Command data missing 'command' field")
                continue

            recent_commands.append(cmd_data)
            if db.insert_command(cmd_data):
                processed += 1

                alerts = analyze_command(cmd_data)
                alerts_generated += len(alerts)
                
                if cmd_data.get('suspicious'):
                    check_suspicious_threshold(cmd_data.get('hostname', 'unknown'))

                if cmd_data.get('suspicious') or alerts:
                    logger.info(f"Suspicious command from {cmd_data.get('hostname')}: "
                              f"{cmd_data.get('command')} {cmd_data.get('args', '')}")
            else:
                logger.error(f"Failed to insert command: {cmd_data}")
        
        response = {
            'status': 'success',
            'processed': processed,
            'alerts_generated': alerts_generated,
            'total_received': len(commands)
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error processing commands: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/commands', methods=['GET'])
def get_commands():
    """Get command logs with filtering options"""
    try:
        limit = request.args.get('limit', 100, type=int)
        suspicious_only = request.args.get('suspicious', 'false').lower() == 'true'
        hostname = request.args.get('hostname')
        hours = request.args.get('hours', 24, type=int)
        
        with sqlite3.connect(DATABASE_FILE) as conn:
            conn.row_factory = sqlite3.Row
            
            query = '''
                SELECT * FROM commands 
                WHERE datetime(received_at) > datetime('now', '-{} hours')
            '''.format(hours)
            params = []
            
            if suspicious_only:
                query += ' AND suspicious = 1'
            
            if hostname:
                query += ' AND hostname = ?'
                params.append(hostname)
            
            query += ' ORDER BY received_at DESC LIMIT ?'
            params.append(limit)
            
            cursor = conn.execute(query, params)
            commands = [dict(row) for row in cursor.fetchall()]
        
        return jsonify({
            'commands': commands,
            'count': len(commands)
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving commands: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    try:
        hours = request.args.get('hours', 24, type=int)
        severity = request.args.get('severity')
        
        with sqlite3.connect(DATABASE_FILE) as conn:
            conn.row_factory = sqlite3.Row
            
            query = '''
                SELECT * FROM alerts 
                WHERE datetime(created_at) > datetime('now', '-{} hours')
            '''.format(hours)
            params = []
            
            if severity:
                query += ' AND severity = ?'
                params.append(severity.upper())
            
            query += ' ORDER BY created_at DESC'
            
            cursor = conn.execute(query, params)
            alerts = [dict(row) for row in cursor.fetchall()]
        
        return jsonify({
            'alerts': alerts,
            'count': len(alerts)
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    try:
        hours = request.args.get('hours', 24, type=int)
        
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.execute('''
                SELECT COUNT(*) FROM commands 
                WHERE datetime(received_at) > datetime('now', '-{} hours')
            '''.format(hours))
            total_commands = cursor.fetchone()[0]
            
            cursor = conn.execute('''
                SELECT COUNT(*) FROM commands 
                WHERE suspicious = 1 AND datetime(received_at) > datetime('now', '-{} hours')
            '''.format(hours))
            suspicious_commands = cursor.fetchone()[0]

            cursor = conn.execute('''
                SELECT COUNT(DISTINCT hostname) FROM commands 
                WHERE datetime(received_at) > datetime('now', '-{} hours')
            '''.format(hours))
            unique_hosts = cursor.fetchone()[0]
            
            cursor = conn.execute('''
                SELECT command, COUNT(*) as count FROM commands 
                WHERE datetime(received_at) > datetime('now', '-{} hours')
                GROUP BY command ORDER BY count DESC LIMIT 10
            '''.format(hours))
            top_commands = [{'command': row[0], 'count': row[1]} for row in cursor.fetchall()]

            cursor = conn.execute('''
                SELECT severity, COUNT(*) as count FROM alerts 
                WHERE datetime(created_at) > datetime('now', '-{} hours')
                GROUP BY severity
            '''.format(hours))
            alerts_by_severity = {row[0]: row[1] for row in cursor.fetchall()}
        
        return jsonify({
            'period_hours': hours,
            'total_commands': total_commands,
            'suspicious_commands': suspicious_commands,
            'unique_hosts': unique_hosts,
            'suspicious_percentage': round((suspicious_commands / max(total_commands, 1)) * 100, 2),
            'top_commands': top_commands,
            'alerts_by_severity': alerts_by_severity,
            'recent_commands_in_memory': len(recent_commands)
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    """Get dashboard data"""
    try:
        recent_suspicious = [
            cmd for cmd in list(recent_commands)[-50:] 
            if cmd.get('suspicious')
        ]

        with sqlite3.connect(DATABASE_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM alerts 
                WHERE severity = 'CRITICAL' 
                AND datetime(created_at) > datetime('now', '-1 hour')
                ORDER BY created_at DESC LIMIT 10
            ''')
            critical_alerts = [dict(row) for row in cursor.fetchall()]
        
        return jsonify({
            'recent_suspicious_commands': recent_suspicious,
            'critical_alerts': critical_alerts,
            'system_status': 'operational',
            'monitoring_active': True
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving dashboard data: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'blueteam_command_logger',
        'version': '1.0',
        'timestamp': datetime.now().isoformat()
    }), 200

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Received shutdown signal, stopping server...")
    sys.exit(0)

def log_monitor():
    """Background thread to monitor and process JSON log file"""
    json_log_path = '/var/log/data.json'
    processed_lines = 0
    
    while True:
        try:

            try:
                with open(json_log_path, 'r') as f:
                    lines = f.readlines()
                    
                new_lines = lines[processed_lines:]
                for line in new_lines:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            recent_commands.append(data)
                            
                            if db.insert_command(data):
                                alerts = analyze_command(data)
                                if data.get('suspicious'):
                                    check_suspicious_threshold(data.get('hostname', 'unknown'))

                                if data.get('suspicious') or alerts:
                                    logger.info(f"File monitor - Suspicious: {data.get('command')} from {data.get('hostname')}")
                        
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in log file: {line}")
                        except Exception as e:
                            logger.error(f"Error processing log line: {e}")
                
                processed_lines = len(lines)
                
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.error(f"Error reading log file: {e}")
                
        except Exception as e:
            logger.error(f"Log monitor error: {e}")

        time.sleep(5)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Starting r0ddy Server")
    logger.info(f"Database: {DATABASE_FILE}")
    logger.info(f"Alert threshold: {ALERT_THRESHOLD_SUSPICIOUS} suspicious commands in {ALERT_WINDOW_MINUTES} minutes")
    
    monitor_thread = threading.Thread(target=log_monitor, daemon=True)
    monitor_thread.start()
    logger.info("Started log file monitor thread")
    
    try:
        app.run(
            host='0.0.0.0',
            port=8080,
            debug=False,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)
