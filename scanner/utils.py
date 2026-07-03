import ipaddress
import re

def is_valid_target(target):
    """
    Kiểm tra input tránh OS Command Injection.
    Chỉ chấp nhận IP (v4/v6), localhost, hoặc domain hợp lệ.
    """
    # Cho phép localhost
    if target == "localhost":
        return True

    # Thử parse IP (IPv4 hoặc IPv6)
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Nếu không phải IP, kiểm tra xem có phải domain hợp lệ
    domain_regex = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if domain_regex.match(target):
        return True
        
    return False