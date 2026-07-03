import sys
from scanner.cli import setup_parser
from scanner.database import init_db, add_target, create_scan, get_history

# Nạp động cơ quét vừa viết
from scanner.engine import run_nmap

def main():
    init_db()
    parser = setup_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        print(f"[*] Đang chuẩn bị quét mục tiêu: {args.target} ({args.type})")
        
        # 1. Lưu Mục tiêu và tạo ID Phiên quét trong Database
        target_id = add_target(args.target)
        scan_id = create_scan(target_id, status="RUNNING")
        
        # 2. Bóp cò: Kích hoạt Nmap thực sự
        xml_output = run_nmap(args.target, args.type)
        
        if xml_output:
            print(f"[+] Tiến trình Nmap hoàn tất! Thu được {len(xml_output)} ký tự dữ liệu XML.")
            # TODO: Cập nhật status thành COMPLETED (sẽ làm sau)
        else:
            print("[-] Quét thất bại.")
            # TODO: Cập nhật status thành FAILED (sẽ làm sau)
            
    elif args.command == "history":
        print(f"[*] Lịch sử quét của: {args.target if args.target else 'Tất cả hệ thống'}")
        print("-" * 50)
        records = get_history(args.target)
        if not records:
            print("[-] Chưa có dữ liệu lịch sử nào.")
        else:
            for rec in records:
                print(f"[{rec['scan_date']}] IP: {rec['target_str']} | Trạng thái: {rec['status']} | Scan ID: {rec['scan_id']}")

if __name__ == "__main__":
    main()