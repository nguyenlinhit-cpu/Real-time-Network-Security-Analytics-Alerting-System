# Rà soát SecNet (lần 2) — Kiểm tra lại toàn bộ tính năng

> Commit được rà: `fb95773` (28/09/2026). Chỉ ghi nhận lỗi, **không sửa code**.
> Bản rà trước (commit `734e38e`, 56 mục) vẫn còn trong lịch sử git: `git show fb95773:SECNET_REVIEW.md`.

## Cách kiểm tra

1. **Build + CI cục bộ:** `cargo build --workspace`, `cargo test --workspace`, `cargo fmt --check`, `cargo clippy -D warnings`, `cargo audit`, `cargo check -p frontend --target wasm32-unknown-unknown`.
2. **Chạy thật end-to-end:** dựng TimescaleDB `2.14.2-pg15` bằng Docker (mount `migrations/` giống `docker-compose.yml`), chạy `backend` và `capture-engine` (simulation, 200 pkt/s, khoảng 2 phút), gọi API bằng `curl` với 3 vai trò admin / analyst / viewer, nghe `/ws/alerts` và `/ws/traffic` bằng `websocat`, rồi đối chiếu với dữ liệu trong DB.
3. **Đọc code:** toàn bộ handler backend, alerting, auth, middleware, Redis client, 8 detector, live capture, simulator, migrations, các trang và component frontend, Dockerfile, nginx, docker-compose.

Các mục ghi **[Đã chạy thử]** là lỗi tái hiện được khi chạy thật. Các mục còn lại phát hiện qua đọc code.

## Tóm tắt

| Hạng mục | Kết quả |
|---|---|
| Build workspace (native + WASM) | ✅ Thành công |
| Test | ✅ 30/30 pass. Tuy vậy không có test nào gọi handler với DB thật, nên lỗi 500 ở mục 1 không bị phát hiện. |
| `cargo fmt --check`, `cargo clippy -D warnings` | ✅ Sạch (job `lint` đã hết lỗi) |
| `cargo audit` | ❌ **1 lỗ hổng** `idna 0.5.0` (RUSTSEC-2024-0421, kéo vào qua `validator 0.18`), nên job `security-audit` trên CI vẫn fail |
| `docker compose up --build` | ❌ **Image backend không build được** (mục 2) |

**5 lỗi nặng nhất:**
1. Mọi API `/api/rules` trả **HTTP 500**, nên trang Rules không dùng được.
2. Dockerfile backend thiếu thư mục `migrations/`, nên `docker compose up --build` lỗi biên dịch.
3. Khoảng **42% traffic bị mất** khi ghi DB, do cột `flags VARCHAR(20)` quá ngắn cho DNS.
4. Mỗi alert được đẩy **2 lần** qua WebSocket (pg_notify bị gọi 2 lần).
5. Xoá một rule thì detector vẫn chạy, và **mọi alert của rule đó bị mất** do lỗi khoá ngoại.

---

# PHẦN A — LỖI CHỨC NĂNG NGHIÊM TRỌNG (🔴)

### 1. Toàn bộ API Rules trả 500 — [Đã chạy thử]
- `DetectionRule` (`crates/common/src/models/rule.rs`) có 2 trường `mitre_tactic` và `mitre_technique`, nhưng mọi câu `SELECT`/`RETURNING` trong `crates/backend/src/handlers/rules.rs` (dòng 30, 62, 104, 154, 174) **không lấy 2 cột này**. `sqlx::FromRow` báo `ColumnNotFound("mitre_tactic")`.
- Hậu quả khi chạy thật:
  - `GET /api/rules` và `GET /api/rules/:id` trả 500, nên trang Rules trống (frontend nuốt lỗi).
  - `PATCH /api/rules/:id` trả 500 ngay ở bước đọc `_existing`, nên **không sửa, bật hay tắt được rule nào**.
  - `POST /api/rules` **vẫn INSERT vào DB** nhưng trả 500 và **không ghi audit log**. Người dùng tưởng thất bại nên bấm lại, và lần sau gặp lỗi trùng tên (`name UNIQUE`).
- Ngoài ra `create_rule` và `update_rule` bỏ qua `mitre_tactic`/`mitre_technique` trong DTO, nên không đặt được MITRE qua API.

### 2. `docker compose up --build` fail: image backend không biên dịch được — [Đã chạy thử]
- `crates/backend/src/main.rs:39` dùng `sqlx::migrate!("../../migrations")`. Macro này nhúng migration **lúc biên dịch**, nhưng `crates/backend/Dockerfile` chỉ `COPY` `Cargo.toml`, `Cargo.lock`, `crates`, `.sqlx` mà **không copy `migrations/`**.
- Tái hiện với đúng build context đó: `error canonicalizing migration directory .../migrations: No such file or directory`.

### 3. Mất ~42% traffic khi ghi vào `traffic_events` — [Đã chạy thử]
- Cột `flags` là `VARCHAR(20)` (`migrations/20260101000005_...sql:14`), trong khi DNS event ghi `flags = "DNS:<tên miền>"` (thường dài hơn 20 ký tự).
- Mỗi batch là một câu `INSERT` duy nhất (`crates/capture-engine/src/main.rs`, `flush_traffic_batch`), nên **chỉ cần 1 event DNS dài là cả batch 100 event bị huỷ**.
- Số đo thực tế: 250 batch lỗi, **19.086 / 45.300 event bị mất**.
- Ở chế độ live, gần như batch nào cũng có truy vấn DNS, nên phần lớn traffic sẽ không được lưu. Trang Traffic, lịch sử thiết bị, top talkers và alert→traffic đều thiếu dữ liệu.

### 4. Alert bị đẩy 2 lần qua WebSocket — [Đã chạy thử]
- Trigger `trigger_notify_new_alert` (`migrations/...013...sql:7`) đã gọi `pg_notify('new_alert')` sau mỗi INSERT. `spawn_alert_persister` (`crates/capture-engine/src/detection/engine.rs:304`) lại gọi `pg_notify('new_alert')` thêm một lần nữa, trong một transaction khác nên Postgres không gộp.
- Đo được **56 message WS cho 28 alert** (mỗi alert đúng 2 lần).
- Hậu quả:
  - Toast và âm báo động kêu 2 lần.
  - Danh sách alert trên UI có bản trùng. `<For key=alert.id>` gặp key trùng nên render lỗi.
  - `dispatch()` chạy 2 lần mỗi alert (lần 2 chỉ bị chặn nhờ throttler).

### 5. Xoá rule thì alert của rule đó bị mất hoàn toàn — [Đã chạy thử]
- `reload_rules_from_db()` chỉ cập nhật detector nào **còn** trong DB. Detector của rule đã xoá vẫn chạy với `rule_id` cũ.
- `INSERT INTO alerts` bị lỗi `violates foreign key constraint "alerts_rule_id_fkey"`, nên alert **không được lưu, không lên WS, không gửi thông báo**. Chỉ có một dòng WARN trong log.
- Hệ quả: nút "Delete rule" trên UI **không tắt được detector**, và còn làm mất cảnh báo.

### 6. ARP Spoofing không bao giờ kích hoạt (cả simulator lẫn live) — [Đã chạy thử]
- `arp_spoof.rs:71` dùng `event.dst_ip` (IP **đích** của gói ARP) làm khoá, nhưng lại ghép với MAC của **người gửi** (`live.rs` ghi `MAC:<sender_hw_addr>`). Phải là ánh xạ *sender IP → sender MAC*.
- **Simulator:** kịch bản ARP luôn gửi cùng MAC giả `de:ad:be:ef:00:01`, nên lần đầu detector "học" MAC giả là MAC hợp lệ (lưu vào `rules_state.json`), và các lần sau không còn gì khác biệt. Kết quả: **0 alert ARP** sau nhiều vòng demo. Baseline còn bị đầu độc vĩnh viễn qua file state.
- **Live:** hai máy khác nhau cùng hỏi ARP một IP (ví dụ cùng hỏi gateway) cũng bị coi là "IP đổi MAC". Alert mức Critical được sinh ra, auto-block **chặn máy hợp lệ**.
- `ip_to_mac` không bao giờ được cập nhật hay dọn. Một thiết bị đổi MAC hợp lệ (thay card mạng, DHCP cấp lại) sẽ bị báo động mỗi 30 giây mãi mãi.

### 7. Auto-block chặn sai IP — [Đã chạy thử]
- SYN Flood đếm theo **đích**, nhưng alert lấy `src_ip` của **gói cuối cùng** (`syn_flood.rs:107`). Khi Port Scan (cũng gửi SYN) chạy cùng lúc, IP của máy quét lọt vào alert SYN Flood.
- Thực tế: `10.0.0.99` (máy Port Scan) bị auto-block với lý do *"SYN Flood"*.
- Với SYN flood thật (src giả mạo hoặc phân tán), hệ thống sẽ chặn một IP ngẫu nhiên, có thể là IP hợp lệ. Kẻ tấn công lợi dụng được để khiến hệ thống tự chặn đối tác.

### 8. Frontend không gửi request logout lên server
- `crates/frontend/src/api/client.rs:71`: `.map(|r| r.send())` chỉ tạo future mà **không `.await`**, nên request `/api/auth/logout` không bao giờ được gửi.
- Access token và refresh token **không bị thu hồi** sau khi bấm Đăng xuất (phía server thu hồi đúng khi gọi trực tiếp; đã chạy thử).
- WebSocket đang mở cũng không bị đóng khi logout, nên vẫn nhận alert.

### 9. Frontend không dùng refresh token, hết hạn là "chết"
- `try_refresh_token()` được viết nhưng **không có chỗ nào gọi**. Không có xử lý HTTP 401.
- Sau 24 giờ mọi API lỗi nhưng UI không báo và không tự đăng xuất. WS reconnect bằng token hết hạn nên thất bại mãi.

### 10. Thao tác alert không cập nhật trên giao diện
- `alerts_table.rs:162` dùng `<For key=|alert| alert.id>`. Khi Acknowledge/Resolve, phần tử được thay bằng bản mới **cùng id**. Leptos giữ nguyên hàng cũ nên badge trạng thái và nút **không đổi** cho tới khi tải lại trang.
- Lỗi (403 do alert đã giao cho analyst khác, 500…) bị nuốt im lặng (`if let Ok(...)`).

---

# PHẦN B — BẢO MẬT (🔴/🟠)

### 11. `POST /api/sensor/heartbeat` không cần xác thực — [Đã chạy thử]
- Route nằm trong `system_routes` (`routes.rs:168`). Bất kỳ ai cũng ghi hoặc ghi đè được trạng thái sensor (đã chèn thử sensor `fake` thành công).
- Kẻ tấn công có thể giả heartbeat `healthy` cho sensor đã chết, hoặc làm rác bảng.

### 12. Lộ secret kênh thông báo cho Viewer/Analyst — [Đã chạy thử]
- `mask_sensitive_config` chỉ che các key chứa `token|password|secret|key`, và chỉ ở cấp 1.
- **Slack `webhook_url`** (bản thân URL là secret) và **object lồng nhau** (ví dụ `headers.Authorization`) **không bị che**. Đã thấy URL Slack đầy đủ và `Bearer abc` khi gọi bằng tài khoản analyst.

### 13. Khoá tài khoản bị lạm dụng và bị vượt qua dễ dàng — [Đã chạy thử]
- Khoá theo **chuỗi username người dùng nhập**. Gửi 5 lần sai mật khẩu cho `analyst` là tài khoản này bị khoá 15 phút, kể cả khi sau đó nhập đúng mật khẩu (tấn công DoS).
- Đăng nhập bằng **email** (`analyst@secnet.local`) của chính tài khoản đang bị khoá thì **vẫn vào được**, vì bộ đếm tách biệt. Kẻ dò mật khẩu có gấp đôi số lần thử.

### 14. Bypass rate-limit bằng header giả — [Đã chạy thử]
- `rate_limit.rs:17` tin `X-Real-IP`/`X-Forwarded-For` do client gửi.
- Backend lắng nghe trực tiếp ở `127.0.0.1:8080`, và frontend `:3000` chuyển tiếp `/api`. Chỉ cần đổi `X-Real-IP` mỗi request là giới hạn 10 req/phút cho `/api/auth/login` không còn tác dụng (12/12 request đều được xử lý).
- Map `rate_limiter`, `failed_logins`, `revoked_tokens` và cache throttler **không bao giờ được dọn**. Với IP giả ngẫu nhiên, bộ nhớ tăng vô hạn.

### 15. Token JWT lộ trong log
- WebSocket truyền `?token=<JWT>` trên URL. nginx (`deploy/nginx/nginx.conf`, dùng log mặc định) ghi **toàn bộ URI kèm token** vào access log.
- Khi mạng lỗi, `reqwest::Error` in kèm URL. Với Telegram, URL chứa **bot token** (`/bot<TOKEN>/sendMessage`), và lỗi này được ghi `warn!` ra log (`telegram.rs`).
- Backend và capture-engine log `DATABASE_URL` **kèm mật khẩu** lúc khởi động (`backend/src/main.rs:35`, `capture-engine/src/main.rs:79`).

### 16. Kiểm tra token WS không nhất quán
- `ws.rs:31` chỉ kiểm tra `revoked_tokens` trong bộ nhớ local, **không kiểm tra Redis** như `is_token_revoked()`. Khi chạy nhiều instance, token đã logout ở instance khác vẫn mở WS được.
- WS đã mở thì không bao giờ kiểm tra lại token (hết hạn hay bị thu hồi vẫn nhận dữ liệu).

### 17. Blocklist nhận giá trị nguy hiểm, không có tác dụng thật — [Đã chạy thử]
- `duration_seconds` rất lớn làm **panic** `TimeDelta::seconds out of bounds` (`blocklist.rs:70`). Server không sập (tokio bắt panic) nhưng client nhận kết nối đứt, không có thông báo lỗi.
- `duration_seconds` âm được chấp nhận và tạo bản ghi đã hết hạn ngay.
- Chặn được `0.0.0.0/0` (toàn bộ Internet) mà không có cảnh báo hay xác nhận.
- `blocked_until` **không được áp dụng ở đâu**: không có job dọn, firewall không gỡ rule sau 2 giờ, API vẫn trả bản ghi đã hết hạn. Chặn thủ công qua UI chỉ ghi DB, không đẩy xuống firewall.
- Auto-block chạy `iptables`/`nft` **bên trong container capture-engine** (mạng bridge), nên không chặn được gì trên host. Bảng `inet filter secnet_blocklist` không được tạo ở đâu. Mỗi lần chặn lại chèn thêm một rule `iptables` trùng.

### 18. Các điểm yếu bảo mật khác
- `/metrics` và `/swagger-ui` công khai, không cần đăng nhập. `/metrics` chạy 4 truy vấn `count(*)` mỗi lần gọi (dễ bị lạm dụng).
- Email gửi bằng `builder_dangerous` (`email.rs:78`), **không TLS/STARTTLS**, nên mật khẩu SMTP đi dạng rõ. Server yêu cầu TLS sẽ từ chối.
- SSRF webhook vẫn dính **DNS rebinding** (kiểm tra DNS xong, `reqwest` lại tự resolve lần nữa).
- Port `3000` của frontend bind `0.0.0.0` (`docker-compose.yml:78`), nên truy cập được qua HTTP thuần từ LAN, **bỏ qua TLS** của nginx.
- Tài khoản seed có mật khẩu công khai trong `WINDOWS_DOCKER_GUIDE.md`, và không có cơ chế buộc đổi mật khẩu.
- Postgres và Redis dùng mật khẩu mặc định / không mật khẩu (chỉ bind `127.0.0.1`).
- Đổi role của user không có hiệu lực tới khi access token hết hạn (24 giờ).
- `refresh_token` có race TOCTOU: hai request đồng thời cùng dùng một refresh token đều qua được.
- Logout thu hồi được refresh token của **người khác** nếu biết chuỗi token (không kiểm tra `sub`).

---

# PHẦN C — ĐỘ CHÍNH XÁC PHÁT HIỆN (🟠)

### 19. DNS Tunneling tạo "bão" alert — [Đã chạy thử]
- Chống lặp theo **tên miền đầy đủ** (`dns_tunneling.rs:103`), mà mỗi truy vấn tunneling có subdomain ngẫu nhiên, nên gần như không có chống lặp.
- Thực tế: **14 alert trong khoảng 1 phút** cho một phiên exfil (nhiều nhất trong mọi loại).
- Chỉ xét nhãn đầu tiên, `min_length` cố định 30. Tunneling dùng nhãn ngắn hoặc nhiều nhãn sẽ lọt.

### 20. Z-Score báo nhầm — [Đã chạy thử]
- Đo **kích thước từng gói** (`zscore_anomaly.rs:116`), không đo lưu lượng theo khoảng thời gian như tên gọi "Traffic Volume". Gói 1.500 byte giữa nhiều gói ACK nhỏ là đủ báo động.
- Thực tế đã sinh alert *"Abnormal traffic spike of **128 bytes**"* ngay trong kịch bản Brute Force.
- EWMA được cập nhật bằng chính giá trị đang xét **trước khi** tính z, nên spike tự làm loãng baseline.

### 21. Port Scan sinh thêm alert Brute-Force
- Quét cổng 20→49 chạm cổng 21, 22, 23, nên mỗi vòng quét sinh thêm 3 alert Brute-Force (đã thấy khi chạy).
- UDP: gói trả lời từ DNS server tới nhiều cổng tạm của client bị đếm như quét cổng.

### 22. Brute-force trên PostgreSQL không bao giờ phát hiện được
- `live.rs:212` bỏ **mọi** gói cổng 5432/6379 (để tránh vòng lặp nội bộ), nhưng cổng 5432 lại nằm trong danh sách `sensitive_ports` của Brute-Force. Tấn công vào Postgres thật trong mạng sẽ không bị phát hiện.

### 23. Cấu hình rule từ DB chỉ áp dụng một phần
- `severity`, `condition_json`, `mitre_*` trong DB **bị bỏ qua**: severity và MITRE hard-code trong từng detector.
- ARP và Beaconing bỏ qua cả `threshold_value` và `time_window_seconds`. DNS bỏ qua `time_window_seconds`. Z-Score bỏ qua `time_window_seconds`.
- Rule tạo mới từ UI **không làm gì cả**, vì engine chỉ có 8 detector cố định.
- Cooldown 30s/60s hard-code. `threshold_value = 0` thì mọi gói đều kích hoạt.
- ICMP dùng `time_window_seconds` không kẹp `max(1)` (khác các detector khác).

### 24. Simulator không demo được đủ 8 rule — [Đã chạy thử]
- Không có kịch bản **ICMP Flood** và **C2 Beaconing**: chạy 2 phút được 0 alert cho 2 rule này.
- Chế độ `all` đổi kịch bản mỗi **60 gói** (`main.rs:283`), nên SYN Flood (250 gói), Port Scan và ARP bị cắt giữa chừng. Với mặc định 20 pkt/s khi chạy ngoài Docker, SYN Flood không bao giờ đạt ngưỡng 200 gói/5 giây.
- Kịch bản Port Scan và ARP không có điểm kết thúc. Kịch bản Volume Spike tạo gói tới 15.000 byte (lớn hơn MTU, không thực tế).

---

# PHẦN D — ỔN ĐỊNH & VẬN HÀNH (🟠/🟡)

### 25. Các cầu nối real-time chết vĩnh viễn khi mất kết nối DB
- Backend: `while let Ok(notification) = listener.recv()` (`main.rs:83`, `main.rs:123`) **thoát vòng lặp ở lỗi đầu tiên**. Postgres restart là WS và thông báo ngừng hẳn cho tới khi restart backend.
- Capture engine: listener `rules_changed` (`main.rs:152`) cũng vậy. Nếu lúc khởi động không kết nối được DB, engine chạy "memory mode" **vĩnh viễn** và mọi alert bị bỏ.
- WS handler: `while let Ok(..) = rx.recv()` thoát khi client chậm bị `Lagged`, nên client bị ngắt. Handler không đọc socket nên không phát hiện client đã đóng cho tới lần gửi kế tiếp.

### 26. Live capture lỗi nhưng báo "healthy"
- Không mở được interface thì log *"Switching to simulation"* (`main.rs:394`) nhưng **không chuyển gì cả**: tiến trình chạy không, heartbeat vẫn báo `healthy`.
- Heartbeat luôn gửi `packets_captured = 0`, `packets_dropped = 0` (đã thấy `packets_captured: 0` sau 45.000 gói), nên trạng thái `degraded` không bao giờ xuất hiện.
- Kênh traffic dùng `try_send` và bỏ gói âm thầm khi đầy. Live capture không xử lý VLAN 802.1Q, IPv6 extension header, fragment. Lỗi đọc gói liên tục gây vòng lặp spam log.
- Trong Docker, capture-engine dùng mạng bridge, nên chế độ live chỉ thấy traffic của chính container (cần `network_mode: host`).

### 27. `/ws/traffic` không phải luồng live thật
- Mỗi batch (tối đa 100 event hoặc 500 ms) chỉ `pg_notify` **1 event mẫu** (`capture-engine/src/main.rs:20`), nên WS chỉ nhận khoảng 2 event/giây dù tải 200–10.000 pkt/s.

### 28. Redis client tự viết
- Một kết nối TCP duy nhất sau `Mutex`, **không có timeout đọc**. Mọi request đều qua rate-limit Redis, nên Redis treo là **toàn bộ API treo**.
- Phản hồi EOF bị hiểu thành `false` (ví dụ "token chưa bị thu hồi") mà không reset kết nối.

### 29. Throttler thông báo gộp nhầm
- Khoá `(rule_id, src_ip)`. Alert có `rule_id = NULL` (rule bị xoá hoặc không khớp) từ các detector khác nhau cùng một IP bị coi là trùng, nên cảnh báo thứ hai không được gửi.

### 30. Kênh thông báo seed hỏng làm rác audit log — [Đã chạy thử]
- 3 kênh seed đều bật nhưng cấu hình không hợp lệ: webhook `http://localhost` bị chặn SSRF, Telegram thiếu `bot_token`, SMTP thiếu tài khoản. Mỗi alert High trở lên sinh 3 dòng `ALERT_NOTIFICATION_*:FAILED` (17 dòng sau 2 phút).
- Nút "Test" kênh trả lỗi chung chung *"An internal server error occurred…"* (`AppError::Internal` bị che), nên người dùng không biết sai ở đâu.
- Email: nhập username rỗng thì vẫn gửi `Credentials("", "")`. Không cấu hình được `from_email` từ UI.

### 31. Migration chạy hai lần và dữ liệu seed bị nhân đôi — [Đã chạy thử]
- Postgres chạy `migrations/*.sql` qua `docker-entrypoint-initdb.d`, sau đó backend chạy `sqlx migrate` lần nữa. Seed traffic không có `ON CONFLICT`, nên mỗi dòng seed xuất hiện 2 lần (dashboard hiển thị 54 gói thay vì 27).
- Migration lỗi chỉ log `warn` rồi **vẫn khởi động** (`main.rs:39-43`).

### 32. Số liệu & hiệu năng
- `/metrics`: `secnet_http_requests_total` luôn bằng 0 (`increment_http_requests()` không được gọi). `uptime` tính từ lần scrape đầu tiên (`init_metrics()` không được gọi).
- `/api/dashboard/summary` quét **toàn bộ** hypertable (SUM + 2 GROUP BY, không giới hạn thời gian) mỗi lần tải. Cột "pkt_count" của top talkers thực ra là **số dòng**, không phải số gói.
- Lọc `src_ip`/`dst_ip` sai định dạng bị bỏ qua âm thầm và trả **toàn bộ** dữ liệu (đã thử `?src_ip=notanip`). `ILIKE` không escape `%`/`_`.
- `PATCH /api/alerts/:id` với `status: "open"` vẫn gán `acknowledged_by` (đã thử), nên alert "mở lại" bị khoá cho analyst đó. Không kiểm tra chuyển trạng thái hợp lệ (ví dụ `resolved` → `open`).
- Export CSV: tham số `format` bị bỏ qua, cắt cứng 1.000 dòng không báo, không có trong OpenAPI. Viewer vẫn export được.
- Audit log: cột `ip_address` luôn `NULL` với login/logout. `UNBLOCK_IP` ghi UUID thay vì IP. `BLOCK_IP` ghi lý do vào cột `target`.

---

# PHẦN E — FRONTEND (🟡)

### 33. Dashboard hiển thị số liệu sai
- "Current throughput" in **tổng byte cộng dồn** với đơn vị "B/s" (`dashboard.rs:93`), nên con số tăng mãi. Nguồn dữ liệu lại chỉ là event mẫu (mục 27).
- "Total detected alerts" là độ dài danh sách đã tải về (tối đa 50–100), không phải tổng thật. `summary.total_alerts` từ API bị bỏ qua.
- "Critical incidents" cũng chỉ đếm trên danh sách cục bộ. Summary chỉ tải một lần, không tự làm mới.

### 34. Rò rỉ tác vụ và bộ nhớ
- `TrafficChart` (`traffic_chart.rs:14`) mỗi lần mount lại `spawn_local` **một vòng lặp vô hạn mới** và không huỷ. Chuyển tab qua lại nhiều lần là có nhiều vòng lặp chạy song song.
- Mỗi lần reconnect WS gọi `forget()` 4 closure. Mỗi alert Critical tạo `AudioContext` mới mà không đóng. Blob URL của CSV không bị `revoke`.

### 35. WebSocket reconnect chậm
- WS khởi động ngay khi mở app, kể cả chưa login. Chưa có token nên bị 401, backoff tăng lên 30 giây. Sau khi login phải **chờ tới 30 giây** mới nhận được alert real-time.
- `backoff_ms` **không bao giờ reset** sau khi kết nối thành công (`ws/client.rs:90`).

### 36. Phân quyền & xử lý lỗi trên UI
- Trang Rules, Blocklist, Settings không ẩn nút theo vai trò. Viewer/Analyst bấm thì nhận 403 **im lặng**, vì hầu hết lời gọi API dùng `if let Ok(..)` và bỏ lỗi.
- Có thể vào thẳng `#settings`, `#audit_logs` bằng hash URL dù không đủ quyền (không có route guard).
- Không có trang **quản lý người dùng** (README có nhắc). API `update_notification_channel` và `get_sensor_status` có sẵn nhưng **UI không dùng**, nên không sửa được kênh và không xem được trạng thái sensor.
- Blocklist trên UI luôn chặn 24 giờ cố định và không hiển thị thời điểm hết hạn.
- Lọc và tìm kiếm alert chỉ chạy trên dữ liệu đã tải về, không có phân trang, không dùng tham số `search` của server.

---

# PHẦN F — CI, PHỤ THUỘC, TÀI LIỆU (🟡)

### 37. `cargo audit` fail
- `idna 0.5.0` (RUSTSEC-2024-0421), kéo vào qua `validator 0.18`. Cần nâng `validator` lên bản dùng `idna >= 1.0`.
- Cảnh báo unmaintained: `paste`, `proc-macro-error`, `proc-macro-error2` (crate cuối còn báo *future-incompat* khi build).

### 38. Kiểm thử thiếu
- 30 test chỉ kiểm tra hàm thuần (hash, JWT, SSRF, throttler, detector). **Không có test handler với DB** (ví dụ `sqlx::test`), nên lỗi 500 của Rules, lỗi `VARCHAR(20)` và lỗi khoá ngoại khi xoá rule đều lọt qua CI.

### 39. Tài liệu lệch với code
- README ghi Admin "quản lý người dùng": không có API hay UI cho việc này.
- `WINDOWS_DOCKER_GUIDE.md` ghi Analyst "quản lý IP blocklist": code chỉ cho Admin.
- `WINDOWS_DOCKER_GUIDE.md` nói demo làm "chuông báo động lập tức kích hoạt": thực tế ARP không bao giờ kích hoạt (mục 6), và ICMP/Beaconing không có kịch bản (mục 24).
- `pipeline.rs` (`RedisStreamBrokerSink`, `LocalChannelSink`) và `process_batch` là code chết.

---

# PHẦN G — TRẠNG THÁI CÁC LỖI TỪ BẢN RÀ TRƯỚC (56 mục)

| # | Nội dung (bản trước) | Trạng thái hiện tại |
|---|---|---|
| 1 | Alert không tới WS/Email/Telegram/Webhook | ✅ Đã nối (PgListener), nhưng ❌ bị đẩy 2 lần (mục 4) |
| 2 | Không ghi `traffic_events` | ⚠️ Đã ghi, nhưng mất ~42% (mục 3) |
| 3 | ARP/DNS chỉ chạy với simulator | ⚠️ Đã parse ARP/DNS ở live, nhưng logic ARP sai (mục 6) |
| 4 | DNS threshold 50 vô hiệu hoá rule | ✅ Đã sửa |
| 5 | Tên rule DB ≠ code | ✅ Đã sửa (seed đổi tên + bảng ánh xạ) |
| 6 | Sửa rule không áp dụng real-time | ⚠️ Đã có `LISTEN rules_changed`, nhưng API sửa rule đang 500 (mục 1), bỏ qua severity (mục 23), rule bị xoá vẫn chạy (mục 5) |
| 7 | WS mở kết nối mới mỗi 5 giây | ✅ Đã sửa. Còn lỗi backoff (mục 35) |
| 8 | CI fail 2/3 job | ⚠️ `lint` đã qua, `security-audit` vẫn fail (mục 37) |
| 9 | Tự đăng ký được Admin | ✅ Đã sửa (đã thử) |
| 10 | WS không xác thực | ✅ Đã sửa (401 khi không có token). Còn mục 16 |
| 11 | Lộ secret kênh | ⚠️ Che một phần. Slack URL và object lồng nhau vẫn lộ (mục 12) |
| 12 | Bypass rate-limit bằng header | ❌ Vẫn còn (mục 14) |
| 13 | CORS wildcard | ⚠️ Có whitelist qua env, nhưng không cấu hình thì vẫn `Any` |
| 14 | JWT secret mẫu qua được kiểm tra production | ✅ Đã sửa |
| 15 | Redis/Postgres expose | ⚠️ Chỉ bind 127.0.0.1, mật khẩu vẫn mặc định |
| 16 | Logout không thu hồi refresh token | ⚠️ Server đã thu hồi, nhưng **frontend không gửi request** (mục 8) |
| 17 | Auto-block tự chặn hạ tầng | ⚠️ Có allowlist, nhưng chặn sai IP (mục 7) và không hiệu lực (mục 17) |
| 18 | Timing attack dò username | ✅ Có dummy hash |
| 19 | Khoá tài khoản bị DoS | ❌ Vẫn còn, thêm lỗi bypass qua email (mục 13) |
| 20 | CSV injection | ✅ Đã sửa |
| 21 | SSRF DNS rebinding | ❌ Vẫn còn (mục 18) |
| 22 | Telegram Markdown không escape | ✅ Đã chuyển sang HTML + escape |
| 24–29 | False positive các detector | ⚠️ Một phần đã sửa (VecDeque, lọc SYN/ACK). Còn mục 6, 19–22 |
| 30 | Map không dọn | ⚠️ Detector đã dọn. Map trong backend chưa (mục 14) |
| 33 | Redis client tự viết | ❌ Vẫn còn (mục 28) |
| 35 | Live capture lỗi âm thầm | ❌ Vẫn còn (mục 26) |
| 36 | Kênh thông báo luôn báo thành công | ✅ Đã trả lỗi, nhưng thông điệp bị che (mục 30) |
| 37 | Email không dùng được với SMTP thật | ❌ Vẫn không có TLS (mục 18) |
| 38 | Slack không hoạt động | ✅ Đã có kênh Slack |
| 39 | `docker compose up` không chạy trên máy sạch | ⚠️ Cert/healthcheck đã sửa, nhưng **build backend fail** (mục 2) |
| 40–41 | Capture trong Docker / blocklist không nhất quán | ❌ Vẫn còn (mục 17, 26) |
| 42 | Migration không áp dụng DB đang chạy | ✅ Đã chạy tự động lúc khởi động. Còn lỗi seed trùng (mục 31) |
| 46 | Frontend không dùng refresh token | ❌ Vẫn còn (mục 9) |
| 47 | Biểu đồ throughput giả | ⚠️ Không còn số ngẫu nhiên, nhưng số liệu sai (mục 33) |
| 48 | Settings lưu sai key kênh | ✅ Đã sửa |
| 49 | Nút sai quyền, lỗi bị nuốt | ❌ Vẫn còn (mục 36) |
| 50–51 | Không tự làm mới, lọc chỉ phía client | ❌ Vẫn còn |
| 52 | Không có routing URL | ✅ Có hash routing (chưa có route guard) |
| 53 | Dùng `js_sys::eval` | ✅ Đã bỏ |
| 54 | Thiếu thao tác quản trị | ❌ Vẫn thiếu quản lý user, sửa kênh, xem sensor |
| 55 | `cargo audit` 2 lỗ hổng | ⚠️ Còn 1 (`idna`) |

---

# Đề xuất thứ tự sửa

1. **Mục 1, 2, 3:** thêm `mitre_*` vào các query của rules, `COPY migrations` trong Dockerfile, nới `flags` lên `TEXT`. Ba sửa nhỏ này mở khoá trang Rules, Docker và dữ liệu traffic.
2. **Mục 4, 5, 8:** bỏ `pg_notify` thừa, tắt detector khi rule bị xoá (hoặc đặt `rule_id = None`), `.await` request logout.
3. **Mục 11–14:** xác thực heartbeat, che secret đệ quy, khoá tài khoản theo user id, chỉ tin header IP từ proxy tin cậy.
4. **Mục 6, 7, 19, 20:** sửa logic ARP, lấy attacker IP đúng cho SYN Flood, chống lặp DNS theo `(src, domain gốc)`, Z-Score theo cửa sổ thời gian.
5. **Mục 25, 26, 9, 10:** tự kết nối lại listener, trạng thái sensor thật, dùng refresh token, sửa `<For>` để UI cập nhật.
6. Thêm test tích hợp dùng DB thật (`sqlx::test`) cho các handler, và nâng `validator` để CI qua `cargo audit`.
