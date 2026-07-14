#Automated Vulnerability Scanner (CLI)

Một công cụ rà quét và quản lý lỗ hổng bảo mật tự động, được thiết kế tối giản trên giao diện dòng lệnh (CLI). Dự án tập trung vào tính cơ động, khả năng trích xuất dữ liệu lỗ hổng chuẩn quốc tế (Threat Intelligence).

## Tính năng nổi bật

* **Rà quét Bề mặt & Vượt tường lửa:** Tự động nhận diện cổng mở và phiên bản dịch vụ. Tích hợp cơ chế bỏ qua Ping (`-Pn`) để vượt qua các tường lửa cấu hình ẩn danh (Stealth mode).
* **Threat Intelligence (CVE & CVSS):** Tích hợp Nmap Scripting Engine (NSE) để thực hiện Active Probing, tự động bóc tách và đối chiếu phiên bản phần mềm để lấy mã định danh lỗ hổng quốc tế (CVE ID) và điểm rủi ro (CVSS Score).
* **Đánh giá rủi ro (Triage):** Tự động phân tích dữ liệu XML trong RAM, gán nhãn rủi ro (Critical, High, Medium) dựa trên điểm CVSS động hoặc ánh xạ cổng tĩnh.
* **Lưu trữ Offline an toàn:** Sử dụng cơ sở dữ liệu `SQLite` nhúng trực tiếp, giúp hệ thống hoạt động độc lập 100% trong môi trường mạng cách ly (Air-gapped) mà không cần máy chủ ngoại vi.
* **Bảo vệ hệ thống (Defensive Design):** Tích hợp bộ lọc Strict Input Validation bằng Regex, chặn đứng mọi nỗ lực tấn công OS Command Injection từ phía người dùng.
* **CI/CD Readiness:** Xuất báo cáo cấu trúc chuẩn `JSON` và `CSV`

##  Cài đặt

Clone :

git clone https://github.com/Hivx165/vuln_scanner_cli.git
cd vuln_scanner_cli
```
