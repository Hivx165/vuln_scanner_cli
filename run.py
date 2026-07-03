import sys
from scanner.cli import setup_parser

def main():
    parser = setup_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        print(f"[*] Đang khởi chạy quét mục tiêu: {args.target} ({args.type})")
    elif args.command == "history":
        print(f"[*] Đang truy xuất lịch sử cho: {args.target if args.target else 'Tất cả'}")

if __name__ == "__main__":
    main()