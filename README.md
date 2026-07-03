# Automated Vulnerability Scanner (CLI)

Một công cụ rà quét và quản lý lỗ hổng bảo mật tự động, được thiết kế tối giản trên giao diện dòng lệnh (CLI). Dự án tập trung vào tính cơ động, không phụ thuộc vào máy chủ ngoại vi và phù hợp để tích hợp vào các luồng kiểm thử liên tục (CI/CD Pipeline).

## Tính năng cốt lõi

- **Quét tự động:** Kích hoạt ngầm tiến trình `nmap`, tự động thu thập thông tin cổng mở và phiên bản dịch vụ.
- **Đánh giá rủi ro (Triage):** Tự động bóc tách dữ liệu XML và gán nhãn mức độ nghiêm trọng (Low, Medium, High, Critical).
- **Lưu trữ Offline:** Ghi nhận toàn bộ lịch sử quét vào cơ sở dữ liệu `SQLite` nhúng trực tiếp, hoạt động hoàn hảo trong mạng cách ly (Air-gapped).
- **Kiểm duyệt đầu vào:** Tích hợp bộ lọc Regex bảo vệ hệ thống khỏi các cuộc tấn công OS Command Injection.
- **Trích xuất báo cáo:** Hỗ trợ xuất dữ liệu ra định dạng `JSON` (cho CI/CD) hoặc `CSV` (cho báo cáo quản lý).

## hệ thống

- Hệ điều hành: Linux 
- Công cụ lõi: Cài đặt sẵn `nmap` ở tầng hệ điều hành.
- Ngôn ngữ: Python 3.

## Cài đặt

Clone kho lưu trữ và chạy trực tiếp không cần cài đặt các thư viện bên ngoài (Sử dụng 100% Python Standard Library).

```bash
git clone https://github.com/Hivx165/vuln_scanner_cli.git
cd vuln_scanner_cli
```
