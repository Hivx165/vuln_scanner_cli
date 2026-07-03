import argparse

def setup_parser():
    parser = argparse.ArgumentParser(
        description="🛡️ DevSecOps Automated Vulnerability Scanner CLI",
        epilog="Ví dụ: python3 run.py scan --target 192.168.1.1"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Các chức năng chính")

    # 1. Lệnh SCAN
    scan_parser = subparsers.add_parser("scan", help="Quét mục tiêu")
    scan_parser.add_argument("-t", "--target", required=True, help="IP hoặc Domain")
    scan_parser.add_argument("--type", choices=['quick', 'full'], default='quick', help="Chế độ quét")

    # 2. Lệnh HISTORY
    history_parser = subparsers.add_parser("history", help="Xem lịch sử quét")
    history_parser.add_argument("-t", "--target", help="Lọc theo IP")

    # 3. Lệnh EXPORT (Đây là phần bạn đang thiếu)
    export_parser = subparsers.add_parser("export", help="Trích xuất dữ liệu báo cáo hệ thống")
    export_parser.add_argument(
        "--format", 
        choices=['json', 'csv'], 
        default='json', 
        help="Định dạng file xuất (mặc định: json)"
    )

    return parser