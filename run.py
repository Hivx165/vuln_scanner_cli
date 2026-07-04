import sys
from scanner.cli import setup_parser
from scanner.database import init_db, add_target, create_scan, get_history, update_scan_status, add_vulnerability, get_all_vulnerabilities
from scanner.reporter import print_scan_results, export_to_json, export_to_csv
from scanner.engine import run_nmap, parse_nmap_xml, assess_severity

# Chống OS Command Injection bằng cách kiểm tra input
from scanner.utils import is_valid_target

def main():
    init_db()
    parser = setup_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        # Xác thực input trước khi truyền cho subprocess
        if not is_valid_target(args.target):
            print(f"LỖI : target '{args.target}' không hợp lệ!")
            sys.exit(1)

        print(f"[*] Khởi chạy quét target: {args.target} ({args.type})")
        target_id = add_target(args.target)
        scan_id = create_scan(target_id, status="RUNNING")
        
        xml_output = run_nmap(args.target, args.type)
        
        if xml_output:
            open_ports = parse_nmap_xml(xml_output)
            print(f"Thu thập đã xong. Tiến hành phân tích nguy cơ")
            
            for p in open_ports:
                p['severity'] = assess_severity(p['port'])
                add_vulnerability(scan_id, p['port'], p['service'], p['severity'])
            
            print_scan_results(args.target, open_ports, scan_id)
            
            update_scan_status(scan_id, "COMPLETED")
            print("Đã lưu toàn bộ báo cáo vào cơ sở dữ liệu cục bộ!")
        else:
            update_scan_status(scan_id, "FAILED")
            print("[-] Quét thất bại hoặc mục tiêu không phản hồi.")
            
    elif args.command == "history":
        print(f"[*] Lịch sử quét của: {args.target if args.target else 'Tất cả hệ thống'}")
        records = get_history(args.target)
        if not records:
            print("[-] Chưa có dữ liệu lịch sử nào.")
        else:
            for rec in records:
                print(f"[{rec['scan_date']}] IP: {rec['target_str']} | Trạng thái: {rec['status']} | Scan ID: {rec['scan_id']}")

    elif args.command == "export":
        print(f"[*] Đang tổng hợp dữ liệu hệ thống để xuất định dạng: {args.format.upper()}")
        data = get_all_vulnerabilities()
        
        if not data:
            print("[-] Cơ sở dữ liệu đang trống. Hãy chạy lệnh 'scan' trước khi xuất báo cáo!")
        elif args.format == 'json':
            export_to_json(data)
        elif args.format == 'csv':
            export_to_csv(data)

if __name__ == "__main__":
    main()