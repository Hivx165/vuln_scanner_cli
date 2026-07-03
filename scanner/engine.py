import subprocess

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