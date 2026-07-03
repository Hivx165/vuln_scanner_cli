import argparse

def setup_parser():
    parser = argparse.ArgumentParser(
        description="🛡️ DevSecOps Automated Vulnerability Scanner CLI",
        epilog="Ví dụ: python3 run.py scan --target 192.168.1.1"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Các chức năng chính")

    # Lệnh SCAN
    scan_parser = subparsers.add_parser("scan", help="Quét mục tiêu")
    scan_parser.add_argument("-t", "--target", required=True, help="IP hoặc Domain")
    scan_parser.add_argument("--type", choices=['quick', 'full'], default='quick', help="Chế độ quét")

    # Lệnh HISTORY
    history_parser = subparsers.add_parser("history", help="Xem lịch sử quét")
    history_parser.add_argument("-t", "--target", help="Lọc theo IP")

    return parser