import json
import csv

def print_scan_results(target, open_ports, scan_id):
    """Vẽ bảng kết quả quét"""
    print(f"\nKẾT QUẢ QUÉT BẢO MẬT: {target} (Scan ID: {scan_id})")
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
            
            if cvss != 'N/A' and float(cvss) >= 7.0:
                severity = "Critical"
                
            print(f"{p['port']:<12} | {p['service']:<20} | {severity:<10} | {cve:<15} | {cvss:<5}")

    print("-" * 85)
    print("\n")

def export_to_json(data, filename="report.json"):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"Xuất thành công: {filename}")

def export_to_csv(data, filename="report.csv"):
    if not data:
        return
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    print(f"Xuất thành công: {filename}")

