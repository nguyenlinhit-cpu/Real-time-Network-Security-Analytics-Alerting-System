# 🛡️ Real-time Network Security Analytics & Alerting System (SecNet)

Hệ thống giám sát lưu lượng mạng theo thời gian thực, tự động phát hiện hành vi xâm nhập và tấn công mạng (Port Scan, SYN Flood/DDoS, SSH Brute-Force, ARP Spoofing, DNS Tunneling, Traffic Volume Anomaly), lưu trữ dữ liệu chuỗi thời gian (time-series hypertable) và phát cảnh báo đa kênh (Email, Webhook, Telegram).

---

## 🏛️ 1. Kiến trúc Hệ thống & Luồng Dữ liệu (Architecture & Data Flow)

Hệ thống được thiết kế theo kiến trúc 4 tầng phân tán, module hóa bằng Rust Cargo Workspace, đảm bảo hiệu năng cao, tiêu thụ ít tài nguyên và phân tách ranh giới tin cậy (Trust Boundaries) rõ ràng:

```mermaid
flowchart TD
    subgraph Untrusted_Zone ["Untrusted Network / Ingestion Zone"]
        Net[Network Interface / Raw Sockets]
        Sim[Traffic Attack Simulator]
    end

    subgraph Core_Engine ["Engine Zone (Rust Tokio Runtime)"]
        Capture[Capture Engine: pnet / pcap]
        RingBuffer[Internal Async Channel: mpsc]
        
        subgraph Detection_Pipeline ["Parallel Detection Rules Engine"]
            R1[Port Scan Detector]
            R2[SYN Flood / DDoS Detector]
            R3[Brute-force Detector]
            R4[ARP Spoof Detector]
            R5[DNS Tunneling Detector]
            R6[Z-Score Anomaly Detector]
        end
    end

    subgraph Data_Storage ["Data Persistence (TimescaleDB / PostgreSQL 15+)"]
        DB_Hyper[(traffic_events: HYPERTABLE)]
        DB_Alerts[(alerts & audit_logs)]
        DB_Config[(detection_rules & channels)]
    end

    subgraph API_Alerting ["Backend API & Dispatcher (Axum)"]
        API[Axum REST API / OpenAPI]
        WS[WebSocket Hub: /ws/alerts, /ws/traffic]
        Dispatcher[Multi-channel Alert Dispatcher]
        Throttler[Alert Throttler: DashMap Cooldown]
    end

    subgraph Notification_Channels ["External Notification Sinks"]
        Email[Email / SMTP Transport]
        TG[Telegram Bot API]
        Hook[SIEM / Incident Webhook]
    end

    subgraph Presentation_Layer ["Presentation Layer (Client Browser)"]
        UI[Leptos 0.7 WASM Web Dashboard]
    end

    Net -->|Raw Ethernet Frames| Capture
    Sim -->|Simulated Events| RingBuffer
    Capture -->|Parsed TrafficEvents| RingBuffer
    RingBuffer --> Detection_Pipeline
    RingBuffer -->|Batch Flush 100ms| DB_Hyper

    Detection_Pipeline -->|Persist Alert| DB_Alerts
    Detection_Pipeline -->|Real-time Push| WS
    Detection_Pipeline -->|Incident Event| Throttler
    Throttler -->|Throttled Dispatch| Dispatcher

    DB_Config -.->|Rules & Channels Config| Detection_Pipeline
    DB_Config -.->|Active Sinks| Dispatcher

    Dispatcher --> Email
    Dispatcher --> TG
    Dispatcher --> Hook

    WS -->|Live Stream| UI
    UI -->|REST Queries / Auth / JWT| API
    API -->|Query Time-series & Metrics| DB_Hyper
    API -->|CRUD Rules, Alerts, Blocklist| DB_Alerts
```

### Ranh giới tin cậy (Trust Boundaries):
1. **Raw Network Interface vs Capture Engine:** Dữ liệu gói tin mạng đến từ bên ngoài là hoàn toàn không tin cậy (*untrusted*). Parser của `capture-engine` giải mã an toàn bộ nhớ (memory-safe) thông qua Rust `pnet`, kiểm tra độ dài buffer, cờ giao thức trước khi đẩy vào pipeline.
2. **Backend API vs Client Browser:** Giao tiếp qua giao thức bảo mật (HTTPS/WSS). Xác thực bắt buộc bằng JWT (chu kỳ 24h, kèm refresh token), băm mật khẩu với Argon2id. Middleware kiểm soát truy cập theo vai trò (RBAC: Admin, Analyst, Viewer) enforce ở phía server với nguyên tắc *deny by default*.
3. **Database Access:** Mọi truy vấn từ Backend và Capture Engine đều sử dụng SQLx parameterized queries (`$1, $2...`), ngăn chặn 100% tấn công SQL Injection.
4. **Alert Sinks Dispatcher:** Endpoint Webhook ngoài được kiểm soát nghiêm ngặt nhằm tránh Server-Side Request Forgery (SSRF) và flood kênh cảnh báo qua cơ chế Throttling deduplication.

---

## 📁 2. Cấu trúc Thư mục Cargo Workspace

```
.
├── Cargo.toml                     # Root Cargo Workspace (4 crates)
├── flake.nix                      # Nix Flake môi trường chuẩn (Rust, SQLx, Trunk, Libpcap)
├── flake.lock                     # Khóa dependencies Nix Flake
├── docker-compose.yml             # Docker compose (TimescaleDB, Backend, Frontend)
├── .env.example                   # Biến môi trường mẫu
├── migrations/                    # Bộ 11 migration SQLx chuẩn TimescaleDB
│   ├── 20260101000001_init_extensions_and_enums.sql
│   ├── 20260101000002_create_users_table.sql
│   ├── 20260101000003_create_devices_table.sql
│   ├── 20260101000004_create_detection_rules_table.sql
│   ├── 20260101000005_create_traffic_events_hypertable.sql
│   ├── 20260101000006_create_alerts_table.sql
│   ├── 20260101000007_create_notification_channels_table.sql
│   ├── 20260101000008_create_audit_logs_table.sql
│   ├── 20260101000009_create_blocked_ips_table.sql
│   ├── 20260101000010_create_indexes_and_constraints.sql
│   └── 20260101000011_seed_sample_data.sql
└── crates/
    ├── common/                    # Crate thư viện dùng chung (Models, DTOs, Enums, Envelopes)
    │   ├── src/models/            # User, TrafficEvent, Alert, DetectionRule, Device, BlockedIp
    │   └── tests/model_tests.rs   # Unit tests xác thực models & DTO validation
    ├── capture-engine/            # Module bắt gói tin & bộ luật phát hiện tấn công
    │   ├── src/capture/           # Live sniffer (pnet), Packet parser, Simulator (6 attacks)
    │   ├── src/detection/         # 6 detection rules + RuleEngine
    │   └── tests/detection_tests.rs# Bộ kiểm thử 6/6 kịch bản phát hiện xâm nhập
    ├── backend/                   # REST API Axum, WebSocket, RBAC, Dispatcher
    │   ├── src/auth/              # JWT token management, Argon2id password hashing, RBAC
    │   ├── src/alerting/          # Email, Webhook, Telegram, Throttler, Dispatcher
    │   ├── src/handlers/          # REST endpoints, WebSockets, Prometheus metrics (/metrics)
    │   ├── src/middleware/        # Rate limiting, Security headers, Correlation ID
    │   └── tests/                 # Integration tests (RBAC, Multi-channel dispatch, Throttling)
    └── frontend/                  # Leptos 0.7 WASM Single Page Application
        ├── src/api/               # REST API client có đính kèm JWT bearer token
        ├── src/ws/                # WebSocket client tự reconnect cho alerts & traffic
        ├── src/components/        # Navbar, Sidebar, TrafficChart (SVG), SeverityDonut, AlertsTable, Toast
        └── src/pages/             # Dashboard, Traffic, Alerts, Rules, Devices, Blocklist, Settings, Login
```

---

## ⚙️ 3. Quy tắc Phát hiện Tấn công (Detection Rules Engine)

| Quy tắc | Phân loại | Độ nghiêm trọng | Thuật toán & Cơ chế phát hiện |
|---|---|---|---|
| **Port Scan** | Scan | Medium | Đếm số lượng distinct destination ports trên 1 cặp `(src_ip, dst_ip)` trong cửa sổ trượt (sliding window). Kích hoạt khi vượt quá `threshold` (mặc định > 20 ports / 10s). |
| **SYN Flood** | DoS / DDoS | Critical | Đếm số lượng gói tin mang cờ `SYN` (không kèm `ACK`) từ 1 `src_ip` gửi tới 1 `dst_ip`. Kích hoạt khi tốc độ SYN vượt ngưỡng (mặc định > 100 pkts / 5s). |
| **Brute-Force** | Credential Access | High | Theo dõi số kết nối bất thường liên tiếp vào các cổng dịch vụ xác thực nhạy cảm (SSH - port 22, RDP - port 3389, FTP - port 21, Telnet - port 23) vượt ngưỡng cho phép. |
| **ARP Spoofing** | Man-in-the-Middle | Critical | Duy trì bảng ánh xạ `IP -> MAC` trong bộ nhớ. Phát hiện khi cùng một địa chỉ IP đột ngột phản hồi với địa chỉ MAC khác lạ, cảnh báo tấn công ARP Poisoning. |
| **DNS Tunneling** | Exfiltration | High | Tính toán Shannon Entropy trên các subdomain của truy vấn DNS (Port 53). Tên miền có độ ngẫu nhiên cao (entropy > 3.8) hoặc độ dài nhãn > 50 ký tự được nhận diện là kênh truyền dữ liệu ngầm. |
| **Z-Score Anomaly** | Volume Anomaly | Medium / High | Sử dụng Welford's algorithm tính toán Mean ($\mu$) và Standard Deviation ($\sigma$) của số byte truyền trên mỗi IP. Cảnh báo khi $Z = \frac{x - \mu}{\sigma} > 3.0$ (vượt quá 3 độ lệch chuẩn). |

---

## 🔔 4. Hệ thống Cảnh báo Đa kênh (Multi-Channel Alerting)

1. **Email Sink (`lettre`):**
   - Kết nối SMTP có TLS/STARTTLS bảo mật.
   - Gửi báo cáo định dạng HTML/Plain-text chuyên nghiệp đến hòm thư quản trị viên.
2. **Telegram Bot Sink (`reqwest`):**
   - Đẩy thông báo tức thời qua Telegram Bot API (`sendMessage`).
   - Hỗ trợ MarkdownV2 formatting, hiển thị icon mức độ nghiêm trọng (🚨 CRITICAL, ⚠️ HIGH, ℹ️ MEDIUM).
3. **Webhook Sink (SIEM / SOAR Integration):**
   - Gửi HTTP POST JSON payload chuẩn hóa tới hệ thống giám sát an ninh bên ngoài.
4. **Alert Throttler & Deduplication (`DashMap`):**
   - Ngăn chặn triệt để hiện tượng **Alert Fatigue** (bão cảnh báo khi mạng bị DDoS hàng triệu gói tin/giây).
   - Khóa deduplication: `hash(rule_id, src_ip, dst_ip)`. Cảnh báo trùng lặp trong cửa sổ cooldown (mặc định 60 giây) sẽ được gom lại và ghi nhận số lượng thay vì gửi ồ ạt.

---

## 🖥️ 5. Giao diện Giám sát Leptos WASM (Frontend SPA)

Giao diện Web SOC (Security Operations Center) hiện đại, xây dựng bằng Rust WebAssembly thuần túy:
- **Dashboard Tổng quan:** Hiển thị 4 thẻ KPI động, đồ thị lưu lượng SVG thời gian thực, biểu đồ tròn phân bổ mức độ nghiêm trọng, top 5 nguồn phát sinh traffic và bảng 5 sự cố mới nhất.
- **Traffic Analysis:** Theo dõi phân bổ theo giao thức (TCP, UDP, ICMP, DNS), bảng chi tiết gói tin với bộ lọc IP/Cổng.
- **Alerts Investigation:** Bảng phân loại sự cố đa năng, lọc theo Severity/Status, tính năng Acknowledge / Resolve sự cố theo phân quyền.
- **Rules Configuration:** Xem danh sách, tạo mới, bật/tắt và điều chỉnh ngưỡng quy tắc phát hiện theo thời gian thực.
- **Device Inventory:** Danh sách thiết bị/node trong mạng, xem lịch sử lưu lượng chi tiết của từng thiết bị.
- **IP Blocklist:** Quản lý danh sách IP bị cách ly, hỗ trợ chặn và gỡ chặn tức thời.
- **Settings & Channel Testing:** Cấu hình kênh Email, Telegram, Webhook và kiểm tra gửi alert mẫu với 1 click.
- **Real-time Engine:** WebSocket client tự động duy trì kết nối tới `/ws/alerts` và `/ws/traffic`, tự động reconnect khi mạng gián đoạn.
- **Audio Alarm:** Tự động phát âm thanh cảnh báo tần số cao (Web Audio API) khi phát hiện sự cố cấp `Critical`.
- **Giao diện Tailwind CSS:** Dark Mode mặc định phong cách Cyberpunk SOC cao cấp, có toggle chuyển đổi Light/Dark.

---

## 🔒 6. Kiểm toán & Tuân thủ OWASP Top 10 (2026)

Hệ thống đã trải qua rà soát toàn diện và đáp ứng các tiêu chuẩn bảo mật khắt khe nhất theo danh mục rủi ro OWASP:

| Mã OWASP | Rủi ro An ninh | Cơ chế Phòng ngừa & Đoạn mã Thực thi cụ thể |
|---|---|---|
| **A01:2026** | **Broken Access Control** | - **Server-side RBAC Enforcement:** Mọi route nhạy cảm được bảo vệ bởi middleware `auth_middleware` với nguyên tắc *deny-by-default* ([`crates/backend/src/auth/middleware.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/auth/middleware.rs)).<br>- **Resource Ownership Verification:** Khi cập nhật/xử lý alert, kiểm tra quyền sở hữu của analyst (`acknowledged_by`); analyst khác không thể can thiệp ngoại trừ Admin ([`crates/backend/src/handlers/alerts.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/handlers/alerts.rs)). |
| **A02:2026** | **Cryptographic Failures** | - **Argon2id Hashing:** Băm mật khẩu người dùng bằng thuật toán Argon2id kèm cryptographically secure salt (`OsRng`) theo chuẩn OWASP ([`crates/backend/src/auth/password.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/auth/password.rs)).<br>- **JWT Tokens:** Sử dụng HS256, thời hạn hết hạn xác định (`exp`), cấp phát kèm refresh token riêng biệt.<br>- **Bảo mật Kênh Truyền:** Ép buộc header `Strict-Transport-Security` (HSTS). Kênh gửi thông báo SMTP sử dụng TLS/STARTTLS. |
| **A03:2026** | **Injection** | - **100% Parameterized SQL:** Toàn bộ thao tác cơ sở dữ liệu qua SQLx đều sử dụng cú pháp tham số `$1, $2...`. Không có bất kỳ đoạn mã nào nối chuỗi SQL thủ công ([`crates/backend/src/handlers/`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/handlers/)).<br>- **Input Validation:** Xác thực định dạng email, độ dài chuỗi, dải IP hợp lệ qua crate `validator` cho toàn bộ các DTO đầu vào ([`crates/common/src/models/`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/common/src/models/)). |
| **A04:2026** | **Insecure Design & SSRF** | - **Trust Boundary Separation:** Tách biệt rõ ràng vùng mạng không tin cậy (raw packet sniffer) và vùng xử lý nghiệp vụ trung tâm.<br>- **Alert Throttler:** Tránh tràn tài nguyên hệ thống khi mạng bị tấn công cường độ lớn.<br>- **Webhook Dispatch Protection:** Kiểm tra URL và giới hạn thời gian timeout request (10s) chống treo kết nối. |
| **A05:2026** | **Security Misconfiguration** | - **Environment Variables:** Không hardcode bất kỳ credential hay API key nào; cảnh báo runtime nếu dùng secret mặc định ([`crates/backend/src/main.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/main.rs)).<br>- **Error Sanitization:** Tắt verbose/debug database error trả về client; ghi log nội bộ qua `tracing::error!` và chỉ phản hồi thông báo generic an toàn ([`crates/backend/src/error.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/error.rs)).<br>- **Security Headers Middleware:** Tự động đính kèm `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Content-Security-Policy` (CSP) ([`crates/backend/src/middleware/security_headers.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/middleware/security_headers.rs)).<br>- **CORS Origin Whitelisting:** Cấu hình whitelist origin cụ thể qua biến `CORS_ALLOWED_ORIGINS` thay vì wildcard.<br>- **Non-root Docker:** Container Backend chạy dưới tài khoản `secnet (uid 1000)` không có quyền root. |
| **A06:2026** | **Vulnerable & Outdated Components** | - **Pinned Dependencies:** 100% các crate trong `Cargo.toml` toàn workspace đều được ghim version cụ thể, tuyệt đối không dùng ký tự `*` bất định.<br>- **Clean Audit Check:** Tuân thủ kiểm tra an toàn chuỗi cung ứng mã nguồn. |
| **A07:2026** | **Identification & Authentication Failures** | - **Rate Limiting:** Giới hạn nghiêm ngặt 10 request/phút đối với các endpoint đăng nhập và đăng ký (`/api/auth/login`, `/api/auth/register`) ([`crates/backend/src/middleware/rate_limit.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/middleware/rate_limit.rs)).<br>- **Account Lockout:** Tự động khóa tạm thời tài khoản trong 15 phút sau 5 lần đăng nhập thất bại liên tiếp ([`crates/backend/src/handlers/auth.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/handlers/auth.rs)).<br>- **Generic Error Messages:** Thông báo đăng nhập sai chung một câu: `"Invalid username or password"`, ngăn chặn việc dò tìm username người dùng (User Enumeration). |
| **A08:2026** | **Software & Data Integrity Failures** | - **Schema Constraints:** Database áp đặt ràng buộc toàn vẹn dữ liệu chặt chẽ (Check constraint email regex, check username length, Foreign Key cascading logic).<br>- **Stateful Verification:** Kiểm tra tính hợp lệ của token và phiên đăng nhập trên từng giao dịch. |
| **A09:2026** | **Security Logging & Monitoring Failures** | - **Audit Logging (`audit_logs`):** Ghi vết đầy đủ mọi hành vi trọng yếu: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `USER_REGISTERED`, `CREATE_RULE`, `UPDATE_RULE`, `DELETE_RULE`, `BLOCK_IP`, `UNBLOCK_IP`, `UPDATE_ALERT_STATUS`, tạo/sửa kênh thông báo ([`crates/backend/src/handlers/`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/handlers/)).<br>- **Structured Logging & Correlation ID:** Middleware tự động sinh và đính kèm `x-request-id` theo dõi vết xuyên suốt toàn bộ vòng đời request ([`crates/backend/src/middleware/correlation.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/middleware/correlation.rs)).<br>- **Prometheus Metrics:** Endpoint chuẩn hóa `/metrics` giám sát sức khỏe và khối lượng xử lý của hệ thống ([`crates/backend/src/handlers/metrics.rs`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/crates/backend/src/handlers/metrics.rs)). |
| **A10:2026** | **Server-Side Request Forgery (SSRF)** | - Kiểm tra định dạng URI và cấu hình cổng của webhook endpoints khi thiết lập kênh thông báo.<br>- Áp dụng timeout ngắn (10s) và giới hạn payload kích thước nhỏ khi gửi cảnh báo ra bên ngoài. |

---

## 🚀 7. Hướng dẫn Cài đặt & Khởi chạy (Getting Started)

### Cách 1: Sử dụng Nix Flake (Môi trường phát triển chuẩn nhất)

Môi trường phát triển Nix bao gồm đầy đủ Rust, Cargo, SQLx CLI, Trunk, wasm-bindgen, libpcap, PostgreSQL tools:

```bash
# 1. Kích hoạt môi trường Nix Flake
nix develop

# 2. Khởi chạy Database TimescaleDB container
docker compose up -d timescaledb

# 3. Chạy toàn bộ migrations
sqlx migrate run --database-url postgres://postgres:postgres@localhost:5432/network_security

# 4. Chạy Backend API Server
cargo run -p backend

# 5. Mở terminal khác: Chạy Frontend Dashboard
cd crates/frontend && trunk serve --port 3000

# 6. Mở terminal khác: Chạy Packet Capture Engine hoặc Simulator
cargo run -p capture-engine
```

Truy cập Dashboard tại: `http://localhost:3000`
Tài khoản mặc định:
- **Admin**: `admin` / `Admin@SecNet2026!`
- **Analyst**: `analyst_linh` / `Analyst@SecNet2026!`
- **Viewer**: `viewer_demo` / `Viewer@SecNet2026!`

Tài liệu Swagger UI API tại: `http://localhost:8080/swagger-ui`
Prometheus Metrics tại: `http://localhost:8080/metrics`

---

### Cách 2: Triển khai hoàn chỉnh bằng Docker Compose (Linux / macOS / Windows)

> 📘 **Người dùng Windows**: Xem hướng dẫn chi tiết dành riêng cho Windows tại [WINDOWS_DOCKER_GUIDE.md](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/WINDOWS_DOCKER_GUIDE.md) hoặc chỉ cần nhấp đúp chuột vào file [`start_docker.bat`](file:///home/linh/Real-time-Network-Security-Analytics-&-Alerting-System/start_docker.bat).

```bash
# 1. Chuẩn bị file cấu hình môi trường (nếu chưa có)
cp .env.example .env

# 2. Build và khởi chạy toàn bộ 4 dịch vụ (TimescaleDB, Backend, Frontend Nginx, Capture Engine)
docker compose up --build -d

# 3. Xem log hoạt động theo thời gian thực
docker compose logs -f
```

---

## 🧪 8. Chạy Kiểm thử & Demo Giả lập Tấn công (Testing & Simulation)

### Chạy toàn bộ Bộ kiểm thử (18 Tests - Passed 100%):
```bash
nix develop --command cargo test --workspace
```
Kết quả kiểm thử bao gồm:
- `detection_tests`: Kiểm thử 6 thuật toán phát hiện tấn công (Port Scan, SYN Flood, Brute Force, ARP Spoof, DNS Tunneling, Z-score Volume Anomaly).
- `alerting_tests` & `alert_multichannel_simulation_test`: Kiểm thử multi-channel dispatch và cơ chế chống bão cảnh báo (Throttling window).
- `api_integration_tests`: Kiểm thử phân quyền RBAC, xác thực JWT, băm mật khẩu Argon2id.
- `model_tests`: Kiểm thử tính toàn vẹn DTO validation, serialize/deserialize, severity ordering.

---

### Hướng dẫn Demo Tấn công qua Simulation Mode:
Bạn có thể kích hoạt giả lập các kịch bản tấn công mạng cụ thể thông qua biến môi trường `DEMO_SCENARIO`:

```bash
# 1. Giả lập tấn công Port Scan (Quét 30 cổng liên tiếp trong vài giây)
DEMO_SCENARIO=port_scan cargo run -p capture-engine

# 2. Giả lập tấn công SYN Flood / DDoS (Bơm hàng loạt gói TCP SYN)
DEMO_SCENARIO=syn_flood cargo run -p capture-engine

# 3. Giả lập tấn công SSH/RDP Brute-Force (Thử đăng nhập dồn dập vào cổng 22)
DEMO_SCENARIO=brute_force cargo run -p capture-engine

# 4. Giả lập tấn công ARP Spoofing / Poisoning (Đổi địa chỉ MAC của Gateway)
DEMO_SCENARIO=arp_spoof cargo run -p capture-engine

# 5. Giả lập rò rỉ dữ liệu qua DNS Tunneling (Subdomain mang Shannon Entropy cao)
DEMO_SCENARIO=dns_tunneling cargo run -p capture-engine

# 6. Giả lập Đột biến Lưu lượng bất thường (Volume Anomaly - Z-score Spike)
DEMO_SCENARIO=volume_spike cargo run -p capture-engine
```

Khi chạy các kịch bản trên:
1. `capture-engine` sẽ bơm các gói tin giả lập vào pipeline.
2. Quy tắc tương ứng sẽ lập tức kích hoạt, tạo bản ghi `alerts` trong cơ sở dữ liệu.
3. Sự cố được đẩy tức thời qua WebSocket (`/ws/alerts`) lên Web Dashboard.
4. Trên giao diện SOC, chuông báo động (Sound Alarm) sẽ reo vang đối với các cảnh báo Critical, toast notification xuất hiện góc màn hình, và thông báo được gửi ngay tới Email/Telegram/Webhook.

---

## 📋 9. Checklist Hoàn thành Đồ án (Phases 0 — 6)

- [x] **Phase 0 (Kiến trúc & Môi trường):** Phân chia 4 crates Cargo Workspace, tạo `flake.nix`, `flake.lock`, `docker-compose.yml`, `.env.example`.
- [x] **Phase 1 (Cơ sở dữ liệu TimescaleDB):** 11 tệp migration SQLx hoàn chỉnh, TimescaleDB hypertable `traffic_events`, thiết lập indexes tối ưu, seed dữ liệu mẫu, Rust models tương ứng.
- [x] **Phase 2 (Packet Capture & Detection Engine):** Bộ bắt gói tin live `pnet`, 6 kịch bản giả lập simulator, 6 quy tắc phát hiện xâm nhập chuẩn xác, kiểm thử unit test 6/6.
- [x] **Phase 3 (Backend API & WebSockets):** Axum REST API hoàn chỉnh, xác thực Argon2id, JWT, phân quyền RBAC 3 vai trò, WebSockets `/ws/alerts` & `/ws/traffic`, rate limit, tài liệu Swagger UI.
- [x] **Phase 4 (Hệ thống Cảnh báo Đa kênh):** Kênh Email (`lettre`), Telegram Bot, Webhook, cơ chế chống bão cảnh báo `AlertThrottler` (cooldown 60s), audit log dispatch.
- [x] **Phase 5 (Frontend Dashboard Leptos WASM):** 7 trang chức năng hoàn chỉnh, REST API client, WebSocket auto-reconnect client, biểu đồ SVG thời gian thực, audio alarm Web Audio API, responsive Tailwind CSS Dark Mode.
- [x] **Phase 6 (Bảo mật OWASP Top 10 & Hoàn thiện):** Resource ownership enforcement, bảo vệ chống brute force & account lockout 15 phút, sanitize thông báo lỗi, correlation ID `x-request-id`, Prometheus `/metrics`, Docker non-root user, bảo vệ chống SSRF.
