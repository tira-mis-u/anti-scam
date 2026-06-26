# anti-scam-extension


**AntiScam** là tiện ích mở rộng giúp phát hiện các trang web lừa đảo (phishing) và cảnh báo người dùng khi truy cập. Dự án này được phát triển, cập nhật và nâng cấp sâu rộng dựa trên mã nguồn của **ChongLuaDao**, mang lại khả năng quét toàn diện hơn và tối ưu hóa trải nghiệm người dùng.

Mô hình học máy phân loại được chạy trực tiếp trên trình duyệt, kết hợp cùng cơ chế Heuristic nội bộ giúp phát hiện các hành vi lừa đảo tinh vi một cách tức thời.

Mã nguồn gốc được phát triển dựa trên dự án [Phishing Site Detector Plugin](https://github.com/picopalette/phishing-detection-plugin).

Mã nguồn của browser extension [ChongLuaDao](https://github.com/7zones/chongluadao-extension).

# Những chức năng của extension

| Chức năng | Mô tả |
|-----------|-------|
| 🔍 **Quét & Phân tích URL** | Kiểm tra mức độ an toàn của đường dẫn, tên miền, IP và tuổi đời trang web. |
| 🧠 **Chấm điểm thông minh** | Đánh giá độ tin cậy và cảnh báo rủi ro dựa trên thuật toán đa tầng. |
| 🎭 **Chống giả mạo** | Phát hiện web nhái thương hiệu ngân hàng, ví điện tử, trang thương mại lớn. |
| 📋 **Bảo vệ dữ liệu** | Cảnh báo khi có form nhập mật khẩu, OTP hoặc thẻ tín dụng đáng ngờ. |
| 💻 **Ngăn chặn mã độc** | Phân tích JavaScript lạ, chặn tải file nguy hiểm và chuyển hướng rủi ro. |
| 🗄️ **Cảnh báo thời gian thực** | Đối chiếu với cơ sở dữ liệu blacklist/whitelist cập nhật liên tục từ cộng đồng. |

---

# Hướng dẫn trải nghiệm phiên bản dành cho nhà phát triển

Bạn có thể cài đặt và sử dụng tiện ích trên Chrome (hoặc các trình duyệt nền tảng Chromium) theo các bước sau:

1. Truy cập địa chỉ `chrome://extensions/`
2. Bật **Developer mode (Chế độ nhà phát triển)** ở góc trên bên phải
3. Chọn **Load unpacked (Tải tiện ích chưa đóng gói)** và trỏ đến thư mục `frontend`
4. Nếu cần, hãy ghim (Pin) tiện ích lên thanh công cụ trình duyệt
5. Có thể sẽ xuất hiện một số lỗi do đây là phiên bản đang phát triển, bạn có thể bỏ qua
6. Bắt đầu sử dụng tiện ích

# Thiết lập môi trường phát triển cục bộ (Local Development)

Cài đặt các thư viện cần thiết:

```bash
npm i
```

Nếu chưa có thư mục `build` hoặc `build-firefox`, hãy tạo chúng:
```bash
mkdir build
mkdir build-firefox
```

## Build cho Chrome
```bash
npm run build
```

## Build cho Firefox
```bash
npm run build-firefox
```
Sau đó, vào thư mục `build-firefox` và xóa thuộc tính `incognito` trong tệp `manifest.json`.