import subprocess
import xml.etree.ElementTree as ET
import re

def run_nmap(target, scan_type="quick"):
    """Thực thi Nmap qua subprocess"""
    if scan_type == "quick":
        # Quét nhanh không check CVE
        nmap_args = ["nmap", "-Pn", "-F", "-T4", "-oX", "-", target]
    else:
        # Quét toàn diện, kích hoạt thư viện lỗ hổng NSE
        nmap_args = ["nmap", "-Pn", "-sV", "--script", "vuln", "-T4", "-oX", "-", target]

    try:
        result = subprocess.run(nmap_args, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap error: {e}")
        return None

def parse_nmap_xml(xml_data):
    """Bóc tách XML lấy Port, Service, CVE và CVSS"""
    root = ET.fromstring(xml_data)
    open_ports = []
    
    for host in root.findall('host'):
        for port_element in host.findall('.//port'):
            state = port_element.find('state')
            if state is not None and state.get('state') == 'open':
                port_id = int(port_element.get('portid'))
                service_element = port_element.find('service')
                service_name = service_element.get('name') if service_element is not None else 'unknown'
                
                # Truy quét CVE và CVSS từ script output bằng Regex
                cve_data = []
                for script in port_element.findall('script'):
                    output = script.get('output', '')
                    matches = re.findall(r'(CVE-\d{4}-\d+).*?(\d+\.\d+)', output)
                    if matches:
                        cve_data.extend(matches)
                
                # Chọn CVE có điểm CVSS cao nhất nếu có nhiều lỗ hổng
                if cve_data:
                    cve_data.sort(key=lambda x: float(x[1]), reverse=True)
                    top_cve = cve_data[0][0]
                    top_cvss = cve_data[0][1]
                else:
                    top_cve = "N/A"
                    top_cvss = "N/A"

                open_ports.append({
                    'port': port_id,
                    'service': service_name,
                    'cve_id': top_cve,
                    'cvss_score': top_cvss
                })
    return open_ports

def assess_severity(port):
    """Đánh giá rủi ro cơ sở theo nhóm cổng (Sẽ bị ghi đè nếu có CVSS)"""
    critical_ports = [22, 23, 3389]
    high_ports = [80, 443, 8080, 3306, 5432]
    if port in critical_ports:
        return "Critical"
    elif port in high_ports:
        return "High"
    return "Medium"