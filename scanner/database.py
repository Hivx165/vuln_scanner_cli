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