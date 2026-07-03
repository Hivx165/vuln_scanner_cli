import subprocess
import xml.etree.ElementTree as ET # Thư viện Parser tích hợp sẵn của Python

def run_nmap(target, scan_type="quick"):
    """
    Gọi tiến trình Nmap dưới tầng hệ điều hành.
    Thay vì xuất ra file .xml, chúng ta ép Nmap xuất XML thẳng ra màn hình (stdout) 
    để Python bắt lấy ngay lập tức, không để lại "rác" trên ổ cứng.
    """
    if scan_type == "quick":
        # -F: Fast mode (Quét 100 port phổ biến nhất)
        # -T4: Timing template (Tăng tốc độ quét)
        # -oX - : Xuất XML thẳng ra luồng tiêu chuẩn (stdout)
        nmap_args = ["nmap", "-F", "-T4", "-oX", "-", target]
    else:
        # -sV: Quét sâu để lấy phiên bản dịch vụ (Service Version)
        nmap_args = ["nmap", "-sV", "-T4", "-oX", "-", target]

    print(f"[>] Đang gọi tiến trình OS: {' '.join(nmap_args)}")

    try:
        # Kích hoạt subprocess chạy ngầm lệnh Linux
        result = subprocess.run(
            nmap_args,
            capture_output=True, # Bắt lại những gì Nmap in ra
            text=True,           # Chuyển dữ liệu nhị phân thành chuỗi (String)
            check=True           # Tự văng lỗi nếu câu lệnh xịt (VD: gõ sai IP)
        )
        return result.stdout # Trả về toàn bộ cục dữ liệu XML

    except FileNotFoundError:
        print("[-] Lỗi: Không tìm thấy trình quét Nmap trên hệ thống Linux này.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[-] Tiến trình Nmap thất bại. Lỗi: {e.stderr.strip()}")
        return None

def parse_nmap_xml(xml_string):
    """Mổ xẻ chuỗi XML thô, trích xuất danh sách các cổng đang MỞ."""
    open_ports = []
    if not xml_string:
        return open_ports
    
    try:
        # Biến chuỗi text thành một cây cấu trúc XML
        root = ET.fromstring(xml_string)
        
        # Lùng sục tìm tất cả các thẻ <port> trong dữ liệu
        for port_element in root.findall('.//port'):
            state = port_element.find('state')
            # Nếu cổng đang mở thì mới quan tâm
            if state is not None and state.get('state') == 'open':
                port_id = int(port_element.get('portid'))
                
                # Cố gắng lấy tên dịch vụ (HTTP, SSH, FTP...)
                service_element = port_element.find('service')
                service_name = "unknown"
                if service_element is not None:
                    service_name = service_element.get('name', 'unknown')
                    # Nếu có phiên bản (version) thì gắp luôn
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
    """
    Nội suy mức độ nguy hiểm dựa trên số cổng. 
    (Luồng DevSecOps Triage cơ bản).
    """
    # Các cổng quản trị từ xa thường bị Hacker nhắm tới đầu tiên
    critical_ports = [21, 22, 23, 3389, 445, 139] # FTP, SSH, Telnet, RDP, SMB
    
    # Các cổng dịch vụ web và Database (Dễ bị SQLi, XSS)
    high_ports = [80, 443, 8080, 8443, 3306, 5432, 27017] 
    
    if port in critical_ports:
        return "Critical"
    elif port in high_ports:
        return "High"
    else:
        return "Medium"