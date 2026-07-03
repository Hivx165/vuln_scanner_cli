import argparse

def setup_parser():
    parser = argparse.ArgumentParser(
        description="Automated Vulnerability Scanner CLI",
        epilog="Example: python3 run.py scan --target 192.168.1.1"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Chức năng chính")

    # Lệnh quét
    scan_parser = subparsers.add_parser("scan", help="Quét các mục tiêu")
    scan_parser.add_argument("-t", "--target", required=True, help="Địa chỉ IP hoặc Tên miền")
    scan_parser.add_argument("--type", choices=['quick', 'full'], default='quick', help="Chế độ quét")

    # Lệnh xem lịch sử
    history_parser = subparsers.add_parser("history", help="Xem lịch sử quét")
    history_parser.add_argument("-t", "--target", help="Lọc theo IP")

    return parser