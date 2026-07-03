import sys
from scanner.cli import setup_parser

def main():
    parser = setup_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        print(f"[*] Initiating target scan: {args.target} ({args.type})")
    elif args.command == "history":
        print(f"[*] Retrieving history for: {args.target if args.target else 'All'}")

if __name__ == "__main__":
    main()