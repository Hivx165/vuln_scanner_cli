import sqlite3
import os

# Lưu database tại thư mục gốc để dễ truy cập và di chuyển
DB_FILE = "vuln_data.db"

def get_connection():
    """Tạo kết nối SQLite trả về dữ liệu dạng từ điển."""
    conn = sqlite3.connect(DB_FILE)
    # Trả về hàng dữ liệu dưới dạng dictionary để dễ truy cập
    conn.row_factory = sqlite3.Row 
    return conn

def init_db():
    """Khởi tạo schema database khi chạy lần đầu."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Tránh lưu trùng lặp mục tiêu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_str TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Theo dõi hoạt động quét liên kết với các mục tiêu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            status TEXT,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (target_id) REFERENCES targets (id)
        )
    ''')
    
    # Ghi lại lỗ hổng và cổng mở được phát hiện từ mỗi lần quét
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            service TEXT,
            severity TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    ''')

    conn.commit()
    conn.close()

def add_target(target_str):
    """Thêm mục tiêu mới vào bảng targets. Nếu đã có thì bỏ qua."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Dùng INSERT OR IGNORE để tránh lỗi sập app nếu IP đã tồn tại (UNIQUE)
    cursor.execute('INSERT OR IGNORE INTO targets (target_str) VALUES (?)', (target_str,))
    conn.commit()
    
    # Lấy ID của mục tiêu này (dù vừa thêm mới hay đã có từ trước)
    cursor.execute('SELECT id FROM targets WHERE target_str = ?', (target_str,))
    target_id = cursor.fetchone()['id']
    
    conn.close()
    return target_id

def create_scan(target_id, status="RUNNING"):
    """Tạo một phiên quét mới và trả về ID của phiên đó."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('INSERT INTO scans (target_id, status) VALUES (?, ?)', (target_id, status))
    conn.commit()
    scan_id = cursor.lastrowid
    
    conn.close()
    return scan_id

def get_history(target_str=None):
    """Lấy lịch sử quét. Nếu truyền target_str thì chỉ lấy của IP đó."""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT targets.target_str, scans.id as scan_id, scans.status, scans.scan_date 
        FROM scans 
        JOIN targets ON scans.target_id = targets.id
    '''
    params = ()
    
    if target_str:
        query += ' WHERE targets.target_str = ?'
        params = (target_str,)
        
    query += ' ORDER BY scans.scan_date DESC'
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def update_scan_status(scan_id, status):
    """Cập nhật trạng thái của phiên quét (Ví dụ: RUNNING -> COMPLETED)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE scans SET status = ? WHERE id = ?', (status, scan_id))
    conn.commit()
    conn.close()

def add_vulnerability(scan_id, port, service, severity):
    """Lưu thông tin cổng đang mở (nguy cơ tiềm ẩn) vào DB."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO vulnerabilities (scan_id, port, service, severity)
        VALUES (?, ?, ?, ?)
    ''', (scan_id, port, service, severity))
    conn.commit()
    conn.close()

def get_all_vulnerabilities():
    """Lấy toàn bộ dữ liệu lỗ hổng đã quét được để xuất báo cáo."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # JOIN 3 bảng lại với nhau để lấy thông tin đầy đủ nhất
    query = '''
        SELECT targets.target_str as target, scans.scan_date, 
               vulnerabilities.port, vulnerabilities.service, vulnerabilities.severity
        FROM vulnerabilities
        JOIN scans ON vulnerabilities.scan_id = scans.id
        JOIN targets ON scans.target_id = targets.id
        ORDER BY scans.scan_date DESC
    '''
    
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    
    # Chuyển dữ liệu SQLite thành danh sách Dictionary chuẩn của Python
    return [dict(row) for row in rows]