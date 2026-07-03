import argparse

def setup_parser():
    parser = argparse.ArgumentParser(
        description="Automated Vulnerability Scanner CLI",
        epilog="Example: python3 run.py scan --target 192.168.1.1"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Main functions")

    #SCAN
    scan_parser = subparsers.add_parser("scan", help="Scan targets")
    scan_parser.add_argument("-t", "--target", required=True, help="IP or Domain")
    scan_parser.add_argument("--type", choices=['quick', 'full'], default='quick', help="Chế độ quét")

    #HISTORY
    history_parser = subparsers.add_parser("history", help="View scan history")
    history_parser.add_argument("-t", "--target", help="Filter by IP")

    return parser