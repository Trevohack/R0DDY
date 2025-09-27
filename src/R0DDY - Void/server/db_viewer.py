import sqlite3 
import sys
import argparse
from datetime import datetime
import os

def connect_database(db_file):
    if not os.path.exists(db_file):
        print(f"Error: Database file '{db_file}' not found")
        return None
    
    try:
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row 
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def print_commands(conn, limit=None, suspicious_only=False, hostname=None, show_alerts=False):
    query = "SELECT * FROM commands WHERE 1=1"
    params = []
    
    if suspicious_only:
        query += " AND suspicious = 1"
    
    if hostname:
        query += " AND hostname = ?"
        params.append(hostname)
    
    query += " ORDER BY received_at DESC"
    
    if limit:
        query += " LIMIT ?"
        params.append(limit)
    
    try:
        cursor = conn.execute(query, params)
        commands = cursor.fetchall()
        
        if not commands:
            print("No commands found matching criteria")
            return
        
        print(f"\n{'='*80}")
        print(f"COMMAND EXECUTION LOG ({len(commands)} entries)")
        print(f"{'='*80}")
        
        for i, cmd in enumerate(commands, 1):
            timestamp = cmd['received_at'] if cmd['received_at'] else cmd['timestamp']
            sus_flag = "[SUSPICIOUS]" if cmd['suspicious'] else ""

            print(f"\n[{i:3d}] {timestamp} {sus_flag}")
            print(f"      Host: {cmd['hostname']} | PID: {cmd['pid']} | UID: {cmd['uid']} | TTY: {cmd['tty']}")
            print(f"      CWD:  {cmd['cwd']}")
            print(f"      CMD:  {cmd['command']} {cmd['args'] or ''}")
            
            if cmd['suspicious']:
                print(f"      *** ALERT: Suspicious command detected ***")
        
        print(f"\n{'='*80}")
        print(f"Total commands: {len(commands)}")
        print(f"{'='*80}\n")
        
    except sqlite3.Error as e:
        print(f"Error querying database: {e}")

def print_alerts(conn, limit=None):
    query = "SELECT * FROM alerts ORDER BY created_at DESC"
    params = []
    
    if limit:
        query += " LIMIT ?"
        params.append(limit)
    
    try:
        cursor = conn.execute(query, params)
        alerts = cursor.fetchall()
        
        if not alerts:
            print("No alerts found")
            return
        
        print(f"\n{'='*80}")
        print(f"SECURITY ALERTS ({len(alerts)} entries)")
        print(f"{'='*80}")
        
        for i, alert in enumerate(alerts, 1):
            print(f"\n[{i:3d}] {alert['created_at']} - [{alert['severity']}]")
            print(f"      Type: {alert['alert_type']}")
            print(f"      Host: {alert['hostname']}")
            print(f"      Description: {alert['description']}")
            if alert['command_count'] and alert['command_count'] > 1:
                print(f"      Command Count: {alert['command_count']}")
        
        print(f"\n{'='*80}")
        print(f"Total alerts: {len(alerts)}")
        print(f"{'='*80}\n")
        
    except sqlite3.Error as e:
        print(f"Error querying alerts: {e}")

def print_statistics(conn):
    try:
        cursor = conn.execute("SELECT COUNT(*) FROM commands")
        total_commands = cursor.fetchone()[0]

        cursor = conn.execute("SELECT COUNT(*) FROM commands WHERE suspicious = 1")
        suspicious_commands = cursor.fetchone()[0]
        
        cursor = conn.execute("SELECT COUNT(DISTINCT hostname) FROM commands")
        unique_hosts = cursor.fetchone()[0]
        
        cursor = conn.execute("SELECT MIN(received_at), MAX(received_at) FROM commands")
        date_range = cursor.fetchone()
        
        cursor = conn.execute("""
            SELECT command, COUNT(*) as count 
            FROM commands 
            GROUP BY command 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_commands = cursor.fetchall()
        
        cursor = conn.execute("""
            SELECT hostname, COUNT(*) as count 
            FROM commands 
            GROUP BY hostname 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_hosts = cursor.fetchall()
        
        print(f"\n{'='*60}")
        print(f"DATABASE STATISTICS")
        print(f"{'='*60}")
        print(f"Total Commands:      {total_commands:,}")
        print(f"Suspicious Commands: {suspicious_commands:,} ({(suspicious_commands/max(total_commands,1)*100):.1f}%)")
        print(f"Unique Hosts:        {unique_hosts}")
        print(f"Date Range:          {date_range[0]} to {date_range[1]}")
        
        print(f"\nTop Commands:")
        for cmd, count in top_commands:
            print(f"  {count:6,} - {cmd}")
        
        print(f"\nTop Hosts:")
        for host, count in top_hosts:
            print(f"  {count:6,} - {host}")
        
        print(f"{'='*60}\n")
        
    except sqlite3.Error as e:
        print(f"Error generating statistics: {e}")

def search_commands(conn, search_term):
    try:
        cursor = conn.execute("""
            SELECT * FROM commands 
            WHERE command LIKE ? OR args LIKE ? 
            ORDER BY received_at DESC
        """, (f'%{search_term}%', f'%{search_term}%'))
        
        commands = cursor.fetchall()
        
        if not commands:
            print(f"No commands found containing '{search_term}'")
            return
        
        print(f"\n{'='*80}")
        print(f"SEARCH RESULTS for '{search_term}' ({len(commands)} matches)")
        print(f"{'='*80}")
        
        for i, cmd in enumerate(commands, 1):
            timestamp = cmd['received_at'] if cmd['received_at'] else cmd['timestamp']
            sus_flag = "[SUSPICIOUS]" if cmd['suspicious'] else ""
            
            print(f"\n[{i:3d}] {timestamp} {sus_flag}")
            print(f"      Host: {cmd['hostname']} | PID: {cmd['pid']}")
            print(f"      CMD:  {cmd['command']} {cmd['args'] or ''}")
        
        print(f"\n{'='*80}")
        print(f"Found {len(commands)} matching commands")
        print(f"{'='*80}\n")
        
    except sqlite3.Error as e:
        print(f"Error searching database: {e}")

def main():
    parser = argparse.ArgumentParser(description='R0DDY - Database Viewer') 
    parser.add_argument('--database', '-d', default='roddy_logs.db',
                       help='Database file path (default: roddy_logs.db)')
    parser.add_argument('--limit', '-l', type=int,
                       help='Limit number of results')
    parser.add_argument('--suspicious', '-s', action='store_true',
                       help='Show only suspicious commands')
    parser.add_argument('--hostname', '-H',
                       help='Filter by hostname')
    parser.add_argument('--alerts', '-a', action='store_true',
                       help='Show alerts instead of commands')
    parser.add_argument('--stats', action='store_true',
                       help='Show database statistics')
    parser.add_argument('--search',
                       help='Search for commands containing term')
    parser.add_argument('--all', action='store_true',
                       help='Show all commands (no limit)')
    
    args = parser.parse_args()
    conn = connect_database(args.database)
    if not conn:
        sys.exit(1)
    
    try:
        if args.stats:
            print_statistics(conn)
        elif args.search:
            search_commands(conn, args.search)
        elif args.alerts:
            print_alerts(conn, args.limit)
        else:
            limit = args.limit if args.limit is not None else (None if args.all else 50)
            print_commands(conn, limit, args.suspicious, args.hostname)
            
    finally:
        conn.close()

if __name__ == '__main__':
    main()
