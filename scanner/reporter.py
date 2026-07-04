import json
import csv

def print_scan_results(target, open_ports, scan_id):
    """Vẽ bảng ASCII kết quả quét bao gồm cột CVE và CVSS"""
    print(f"\n[+] KẾT QUẢ QUÉT BẢO MẬT: {target} (Scan ID: {scan_id})")
    print("-" * 85)
    print(f"{'Cổng (Port)':<12} | {'Dịch vụ (Service)':<20} | {'Mức độ':<10} | {'CVE ID':<15} | {'CVSS':<5}")
    print("-" * 85)

    if not open_ports:
        print(f"{'Không phát hiện cổng mở hoặc lỗ hổng nào.':^85}")
    else:
        for p in open_ports:
            severity = p.get('severity', 'Medium')
            cve = p.get('cve_id', 'N/A')
            cvss = p.get('cvss_score', 'N/A')
            
            # Ghi đè mức độ tĩnh nếu điểm CVSS thực tế lớn hơn 7.0
            if cvss != 'N/A' and float(cvss) >= 7.0:
                severity = "Critical"
                
            print(f"{p['port']:<12} | {p['service']:<20} | {severity:<10} | {cve:<15} | {cvss:<5}")

    print("-" * 85)
    print("\n")

def export_to_json(data, filename="report.json"):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"[+] Dữ liệu đã được nén thành công vào: {filename}")

def export_to_csv(data, filename="report.csv"):
    if not data:
        return
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    print(f"[+] Dữ liệu đã được xuất thành công ra: {filename}")