import ipaddress
import re

def is_valid_target(target):
    """
    Hàm kiểm tra định dạng mục tiêu nhập vào.
    Chỉ cho phép IP chuẩn (IPv4/IPv6), 'localhost' hoặc Tên miền hợp lệ.
    Tuyệt đối chặn các ký tự lạ có nguy cơ gây OS Command Injection (như ;, &, |).
    """
    # 1. Bỏ qua nếu là localhost
    if target == "localhost":
        return True

    # 2. Kiểm tra xem có phải IP hợp lệ không (Dùng thư viện ipaddress cực kỳ chuẩn xác)
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass # Nếu không phải IP thì đi tiếp xuống kiểm tra Tên miền

    # 3. Kiểm tra xem có phải Domain hợp lệ không (Dùng Biểu thức chính quy - Regex)
    domain_regex = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if domain_regex.match(target):
        return True
        
    return False