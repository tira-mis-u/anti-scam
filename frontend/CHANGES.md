# BÁO CÁO NÂNG CẤP ENGINE PHÂN TÍCH URL — AntiScam v1.6

> Mục tiêu: chuyển từ mô hình **"một dấu hiệu = nguy hiểm"** sang **"nhiều tín hiệu kết hợp = nguy hiểm"** (corroboration), giảm tối đa false positive, **không thay đổi UI/CSS/layout**.

---

## 1. CÁC FILE ĐÃ THAY ĐỔI

| File | Vai trò | Thay đổi |
|------|---------|----------|
| `frontend/js/heuristic.js` | Engine cục bộ | **Viết lại toàn bộ** — engine `assessRisk()` cộng đồng ý (corroboration) |
| `frontend/js/features.js` | Content script | **Viết lại** — bỏ FP, áp CDN whitelist, thu thập tín hiệu DOM mới |
| `frontend/js/background.js` | Service worker | Thay khối chấm điểm bằng engine mới; giữ nguyên toàn bộ hạ tầng |
| `frontend/js/plugin_ui.js` | Popup UI | **Chỉ thêm** bảng dịch + hiển thị câu giải thích; **không động** HTML/CSS/layout |

> **Không đụng tới:** `plugin_ui.html`, `*.css`, `manifest.json`, `blocking.*`, bố cục badge, biểu đồ, màu sắc.

---

## 2. NGUYÊN TẮC MỚI ĐÃ TRIỂN KHAI

### 2.1 Không kết luận từ 1 tín hiệu đơn lẻ
Mỗi tín hiệu chỉ cộng điểm (base points). Kết luận "nguy hiểm" (≥60) hay "nguy hiểm cao" (≥80) **chỉ đạt được khi nhiều tín hiệu cùng phương hướng xuất hiện** (corroboration bonus).

### 2.2 Rà soát False Positive

| Tín hiệu | Trước đây (FP) | Bây giờ |
|----------|----------------|---------|
| **Favicon** | Đỏ nếu không cùng domain → CDN bị phạt | Chỉ ngờ nếu favicon/brand lạ + KHÔNG phải CDN phổ biến |
| **Tài nguyên ngoài** | Đỏ nếu script/img không cùng domain | Bỏ qua Cloudflare, jsDelivr, Google Fonts, Bootstrap, Font Awesome, Microsoft, Unpkg, CloudFront, Akamai, Fastly… Chỉ ngờ script từ **IP** hoặc domain lạ/obfuscate |
| **iFrame** | Đỏ khi có iframe | Chỉ đỏ khi iframe **ẩn** (0x0 / display:none / opacity:0) hoặc tải từ IP |
| **Chuyển hướng `//`** | Đỏ khi `//` sau vị trí 7 | Chỉ ngờ khi kèm dấu hiệu `//user@` |
| **HTTPS** | Phạt nặng khi thiếu | Tín hiệu rất nhẹ (+6), không tuyệt đối |
| **Dấu `@`** | +20 điểm | +3 điểm nhẹ |
| **Port** | Phạt port lạ | Bỏ qua `:8080 :3000 :5000 :5173 ...` (dev server) |
| **Subdomain** | Phạt >2 dấu chấm | Chỉ ngờ khi ≥4 cấp |
| **Dấu `-`** | Phạt mọi dấu `-` | Chỉ ngờ khi ≥3 dấu `-` |

### 2.3 Tín hiệu mới đã thêm
- **Homograph**: `g00gle`, `micros0ft`, `paypaI`, `arnazon` (dehomoglyph + Levenshtein)
- **Punycode / Unicode**: phát hiện `xn--` và ký tự Unicode bất thường
- **Levenshtein typosquatting**: so với 28 thương hiệu (Google, Microsoft, Vietcombank, BIDV, MB, ACB, Techcombank, TPBank, Agribank, VietinBank, MoMo, ZaloPay…)
- **Tuổi tên miền** (RDAP): <3 ngày / <7 ngày / <30 ngày / <90 ngày
- **Brand impersonation nội dung**: logo/tiêu đề trùng thương hiệu nhưng domain không chính thức
- **Form nhạy cảm**: password, OTP, CVV, card number, CCCD/CMND, KYC/eKYC, số tài khoản
- **Form hijacking**: form gửi chéo sang domain lạ
- **File download**: `.exe .scr .bat .cmd .ps1 .apk .msi .dll .vbs`
- **Obfuscation**: `eval`, `new Function`, `atob`, `fromCharCode`, hex/unicode encoding, entropy cao
- **Keylogger**: theo dõi `keydown`/`keypress` + gửi đi
- **Clipboard hijack**: `navigator.clipboard.writeText`
- **WebSocket / Socket.IO**: chỉ +5 điểm **khi đã có rủi ro khác** (không báo động trên app chat/trading)
- **Từ khoá lừa đảo VN**: `xacminh`, `dinhdanh`, `otp`, `e-kyc`, `nang-cap-bao-mat`, `dong-bo-du-lieu`…

### 2.4 Hệ thống điểm mới (risk score 0–100)

| Mức | Điểm | UI mapping |
|-----|------|------------|
| Nguy hiểm cao | ≥80 | `legitimatePercent ≤ 20` + đỏ |
| Nguy hiểm | 60–79 | đỏ (isPhish) |
| Đáng ngờ | 40–59 | vàng |
| Tương đối an toàn | 20–39 | xanh nhạt |
| An toàn | 0–19 | xanh |

> `legitimatePercent = 100 − riskScore` để **giữ nguyên**语义 UI cũ (càng cao càng an toàn).

### 2.5 Giải thích kết quả (thay jargon kỹ thuật)
Không còn "giảm 1.8% (nhóm C trọng số 6)". Thay bằng câu tiếng Việt phổ thông, ví dụ:
- *"Tên miền có dấu hiệu giả mạo thương hiệu Vietcombank và đồng thời yêu cầu nhập mật khẩu/OTP."*
- *"Trang sử dụng tên miền mới đăng ký và yêu cầu nhập thông tin nhạy cảm."*
- *"Không phát hiện dấu hiệu giả mạo thương hiệu, mã độc hay thu thập dữ liệu nhạy cảm."*

---

## 3. KẾT QUẢ KIỂM THỬ (Node.js)

Chạy: `node frontend/test/test_engine.js`

### Site hợp pháp → An toàn
| Kịch bản | Điểm |
|----------|------|
| Blog dùng Cloudflare + Google Fonts + YouTube iframe | **0** |
| Favicon từ jsDelivr | **0** |
| Dev server `:3000` | **13** |
| URL có dấu `@` | **3** |
| `support.security.microsoft.com` | **0** |
| `www.google.com` | **0** |
| `vietcombank.com.vn` | **10** |

### Trang lừa đảo → Nguy hiểm/Critical
| Kịch bản | Điểm |
|----------|------|
| `vietcombank-login.xyz` + form mk + domain 2 ngày | **100** |
| `g00gle.com` + form đăng nhập | **100** |
| `paypai.com` (chữ I) + form hijack | **100** |
| `micros0ft.com` | **100** |
| `xn--pple-43d.com` (Punycode) | **64** |
| Form gửi chéo domain lạ + obfuscation | **100** |
| `xac-minh-tai-khoan.online` + OTP | **82** |
| Keylogger + tải `.exe` | **84** |

### Biên giới (cân bằng)
| Kịch bản | Điểm |
|----------|------|
| Typosquat `g00gle.com` một mình, domain cũ | **34** (caution — đáng kiểm tra) |
| Typosquat `g00gle.com` + domain mới | **74** (dangerous) |
| `myvietcombank-support.com` cũ, không form | **14** (safe) |

---

## 4. CÁCH ENGINE KẾT HỢP (ví dụ)

```
Logo Vietcombank (brand)        +14
+ Form mật khẩu (form)          +10
+ Domain 2 ngày (age)           +28
= base 52
+ corroboration brand∧form      +24
+ corroboration brand∧age       +18
= riskScore 94 → cap 100  →  CRITICAL
```

Một site chỉ dùng Cloudflare + Google Fonts → **0** (không có corroboration).

---

## 5. TÍNH TƯƠNG THÍCH
- Giữ nguyên **model ML ChongLuaDao** (các key đặc trưng gốc không đổi) → chỉ làm **tín hiệu phụ** (+12 điểm khi ML đồng tình), không tự kết luận → tránh FP từ ML.
- Giữ nguyên **RDAP domain age**, **circuit breaker**, **cache**, **blacklist/whitelist**, **blocking**, **polling UI**.
- `features.js` có fallback `_isTrustedHost` nội bộ (không phụ thuộc `heuristic.js` trong page context).
