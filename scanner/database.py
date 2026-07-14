import sqlite3
from datetime import datetime

DB_NAME = "vuln_data.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row 
    return conn

def init_db():
    """Khởi tạo cơ sở dữ liệu với 3 bảng, bổ sung cột CVE và CVSS"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_str TEXT UNIQUE NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            scan_date TEXT,
            status TEXT,
            FOREIGN KEY(target_id) REFERENCES targets(id)
        )
    ''')
    
    # Bảng này đã được thêm cột cve_id và cvss_score
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            service TEXT,
            severity TEXT,
            cve_id TEXT,
            cvss_score TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    ''')
    
    conn.commit()
    conn.close()

def add_target(target_str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO targets (target_str) VALUES (?)', (target_str,))
    cursor.execute('SELECT id FROM targets WHERE target_str = ?', (target_str,))
    target_id = cursor.fetchone()[0]
    conn.commit()
    conn.close()
    return target_id

def create_scan(target_id, status="PENDING"):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('INSERT INTO scans (target_id, scan_date, status) VALUES (?, ?, ?)', (target_id, now, status))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def update_scan_status(scan_id, status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE scans SET status = ? WHERE id = ?', (status, scan_id))
    conn.commit()
    conn.close()

# Cập nhật hàm này để nhận thêm tham số CVE và CVSS
def add_vulnerability(scan_id, port, service, severity, cve_id="N/A", cvss_score="N/A"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO vulnerabilities (scan_id, port, service, severity, cve_id, cvss_score)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (scan_id, port, service, severity, cve_id, cvss_score))
    conn.commit()
    conn.close()

def get_history(target_filter=None):
    conn = get_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT scans.id as scan_id, targets.target_str, scans.scan_date, scans.status
        FROM scans
        JOIN targets ON scans.target_id = targets.id
    '''
    params = ()
    
    if target_filter:
        query += ' WHERE targets.target_str = ?'
        params = (target_filter,)
        
    query += ' ORDER BY scans.scan_date DESC'
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for row in rows:
        result.append({
            'scan_id': row[0],
            'target_str': row[1],
            'scan_date': row[2],
            'status': row[3]
        })
    return result

# Hàm lấy toàn bộ dữ liệu (cập nhật query lấy thêm CVE/CVSS)
def get_all_vulnerabilities():
    conn = get_connection()
    cursor = conn.cursor()
    query = '''
        SELECT targets.target_str as target, scans.scan_date, 
               vulnerabilities.port, vulnerabilities.service, 
               vulnerabilities.severity, vulnerabilities.cve_id, vulnerabilities.cvss_score
        FROM vulnerabilities
        JOIN scans ON vulnerabilities.scan_id = scans.id
        JOIN targets ON scans.target_id = targets.id
        ORDER BY scans.scan_date DESC
    '''
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

