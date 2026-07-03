import subprocess
import xml.etree.ElementTree as ET

def run_nmap(target, scan_type="quick"):
    """
    Gọi Nmap qua subprocess và nhận kết quả XML từ stdout.
    Tránh tạo file tạm thời trên ổ cứng để tăng tốc độ và bảo mật.
    """
    if scan_type == "quick":
        # Quét 100 port phổ biến nhất với timing aggressive
        nmap_args = ["nmap", "-F", "-T4", "-oX", "-", target]
    else:
        # Quét sâu hơn với xác định phiên bản dịch vụ
        nmap_args = ["nmap", "-sV", "-T4", "-oX", "-", target]

    print(f"[>] Đang gọi tiến trình OS: {' '.join(nmap_args)}")

    try:
        # Chạy Nmap và bắt output XML
        result = subprocess.run(
            nmap_args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout

    except FileNotFoundError:
        print("[-] Lỗi: Không tìm thấy trình quét Nmap trên hệ thống Linux này.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[-] Tiến trình Nmap thất bại. Lỗi: {e.stderr.strip()}")
        return None

def parse_nmap_xml(xml_string):
    """Trích xuất danh sách cổng mở từ XML của Nmap."""
    open_ports = []
    if not xml_string:
        return open_ports
    
    try:
        # Parse XML string thành cây cấu trúc
        root = ET.fromstring(xml_string)
        
        # Lặp qua các cổng, chỉ lấy cổng mở
        for port_element in root.findall('.//port'):
            state = port_element.find('state')
            if state is not None and state.get('state') == 'open':
                port_id = int(port_element.get('portid'))
                
                # Trích xuất tên dịch vụ và phiên bản nếu có
                service_element = port_element.find('service')
                service_name = "unknown"
                if service_element is not None:
                    service_name = service_element.get('name', 'unknown')
                    version = service_element.get('version', '')
                    if version:
                        service_name = f"{service_name} ({version})"
                        
                open_ports.append({
                    'port': port_id,
                    'service': service_name
                })
    except ET.ParseError:
        print("[-] Lỗi: Cấu trúc XML bị hỏng hoặc Nmap trả về dữ liệu rác.")
        
    return open_ports

def assess_severity(port):
    """Đánh giá mức độ rủi ro dựa trên số cổng (heuristic đơn giản)."""
    # Cổng quản trị từ xa - mục tiêu ưu tiên của attacker
    critical_ports = [21, 22, 23, 3389, 445, 139]
    
    # Cổng web và database - dễ bị tấn công ứng dụng (SQLi, XSS)
    high_ports = [80, 443, 8080, 8443, 3306, 5432, 27017] 
    
    if port in critical_ports:
        return "Critical"
    elif port in high_ports:
        return "High"
    else:
        return "Medium"