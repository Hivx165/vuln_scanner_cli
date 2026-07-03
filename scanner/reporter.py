import json
import csv

def print_scan_results(target, open_ports, scan_id):
    """Hiển thị kết quả quét dạng bảng ASCII cho dễ đọc."""
    print(f"\n[+] KẾT QUẢ QUÉT BẢO MẬT: {target} (Scan ID: {scan_id})")
    print("-" * 65)
    print(f"{'Cổng (Port)':<15} | {'Dịch vụ (Service)':<25} | {'Mức độ (Severity)':<15}")
    print("-" * 65)

    if not open_ports:
        print(f"{'Không phát hiện cổng mở hoặc lỗ hổng nào.':^65}")
    else:
        for p in open_ports:
            severity = p.get('severity', 'Medium')
            print(f"{p['port']:<15} | {p['service']:<25} | {severity:<15}")

    print("-" * 65)
    print("\n")

def export_to_json(data, filename="report.json"):
    """Xuất dữ liệu ra file JSON để tích hợp với pipeline CI/CD."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"[+] Dữ liệu đã được nén thành công vào: {filename}")

def export_to_csv(data, filename="report.csv"):
    """Xuất dữ liệu ra file CSV để mở trong Excel hoặc GSheets."""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    print(f"[+] Dữ liệu đã được xuất thành công ra: {filename}")