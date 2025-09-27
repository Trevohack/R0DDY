import sys
import os
import sqlite3 

def main():
    db_file = 'roddy_logs.db' 
    
    if len(sys.argv) > 1:
        db_file = sys.argv[1]
    
    if not os.path.exists(db_file):
        print(f"Database file '{db_file}' not found")
        sys.exit(1)
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.execute("""
            SELECT received_at, hostname, pid, uid, tty, cwd, command, args, suspicious
            FROM commands 
            ORDER BY received_at DESC
        """)
        
        commands = cursor.fetchall()
        
        if not commands:
            print("No commands found in database")
            return
        
        print(f"Command Execution Log - {len(commands)} entries")
        print("=" * 80)
        
        for i, (timestamp, hostname, pid, uid, tty, cwd, command, args, suspicious) in enumerate(commands, 1):
            status = "[SUSPICIOUS]" if suspicious else "[NORMAL]"
            full_cmd = f"{command} {args}" if args else command
            
            print(f"{i:4d}. {timestamp} {status}")
            print(f"      {hostname} | PID:{pid} UID:{uid} TTY:{tty}")
            print(f"      {cwd}")
            print(f"      {full_cmd}")
            print()
        
        suspicious_count = sum(1 for cmd in commands if cmd[8])
        print("=" * 80)
        print(f"Total: {len(commands)} | Suspicious: {suspicious_count} | Normal: {len(commands) - suspicious_count}")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    main() 
