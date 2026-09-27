# Gợi ý nâng cấp — Real-time Network Security Analytics & Alerting System (SecNet)

> Tổng hợp từ việc rà soát code thực tế (README, `capture-engine`, `backend`, `migrations`, `docker-compose.yml`) của repo [nguyenlinhit-cpu/Real-time-Network-Security-Analytics-Alerting-System](https://github.com/nguyenlinhit-cpu/Real-time-Network-Security-Analytics-Alerting-System).

---

## 🔴 Ưu tiên cao — Bug / lỗ hổng thực tế

### 1. README có conflict marker chưa resolve
Cuối file `README.md` (dòng 303–305) còn nguyên:
```
=======
# Real-time-Network-Security-Analytics-Alerting-System
>>>>>>> 08f986271187ea94da73a5dc3e8e98dc917710d6
```
→ Một merge/rebase bị bỏ dở, chưa commit sạch. Cần resolve và dọn lại README.

### 2. Webhook sink không có bảo vệ SSRF như README khẳng định
File: `crates/backend/src/alerting/webhook.rs`

Code chỉ set timeout 5s rồi `POST` thẳng tới `endpoint_url` do người dùng nhập ở trang Settings — **không validate URL**: không chặn `localhost`, `127.0.0.1`, dải IP nội bộ (`10.0.0.0/8`, `169.254.169.254` — cloud metadata endpoint), không giới hạn scheme.

→ Một Analyst/Admin có thể dùng chức năng "test webhook" để dò cổng nội bộ hoặc gọi cloud metadata service. Đây là **SSRF thật**, mâu thuẫn với mục A10:2026 trong README. Cần:
- Chỉ cho phép scheme `https`.
- Resolve DNS rồi kiểm tra IP đích không thuộc dải private/loopback/link-local trước khi gửi.
- Chặn redirect tới địa chỉ nội bộ.

### 3. Rate limiter & alert throttler chỉ hoạt động đúng khi chạy 1 instance
File: `crates/backend/src/middleware/rate_limit.rs` (và `AlertThrottler`)

Cả hai dùng `DashMap` in-memory. Khi scale backend ra nhiều container/pod (điều sẽ cần khi traffic lớn), mỗi instance có bộ đếm riêng → rate-limit login và cơ chế chống "alert storm" (cooldown 60s) mất tác dụng.

→ Nên chuyển sang Redis (`INCR` + `TTL`) để dùng chung giữa các instance.

### 4. `LiveCapture` chỉ parse IPv4
File: `crates/capture-engine/src/capture/live.rs`

Chỉ xử lý `EtherTypes::Ipv4`, bỏ qua hoàn toàn `Ipv6` → mọi rule (Port Scan, SYN Flood, ARP Spoof...) đều "mù" với tấn công qua IPv6.

### 5. `LiveCapture::next_event` polling kiểu busy-loop
`next_event()` dùng `try_recv()` non-blocking, không có cơ chế backpressure/await thật sự → nếu caller loop liên tục khi traffic thấp sẽ busy-spin, tốn CPU vô ích.

---

## 🟡 Kiến trúc & khả năng mở rộng

### 6. Hypertable `traffic_events` chưa có compression / retention policy
Không thấy `add_compression_policy` hay `add_retention_policy` trong `migrations/`. Với traffic ghi liên tục, dữ liệu sẽ phình vô hạn.

→ Thêm compression policy (nén chunk cũ) và retention policy (tự xoá dữ liệu thô sau N ngày, giữ continuous aggregate cho báo cáo dài hạn).

### 7. Chưa có continuous aggregate / rollup cho dashboard
Query traffic theo giờ/ngày hiện có vẻ quét thẳng raw hypertable. Nên thêm `CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)` để dashboard load nhanh khi data lớn.

### 8. Pipeline capture → detection → DB chạy trong 1 process, không có message broker
Hiện dùng `mpsc` nội bộ. Ở quy mô nhỏ ổn, nhưng nếu muốn nhiều `capture-engine` (nhiều node/interface) đẩy vào cùng 1 cụm detection, hoặc scale detection engine độc lập với capture, cần tách qua Kafka/NATS/Redis Streams.

### 9. Detection rules giữ state chỉ trong bộ nhớ
Sliding window, đếm port, bảng ARP IP↔MAC... đều ở RAM. Nếu `capture-engine` restart, toàn bộ trạng thái phát hiện mất sạch (đặc biệt nghiêm trọng với ARP Spoof detector).

→ Cân nhắc snapshot định kỳ ra Redis/DB để rule engine "ấm" lại sau restart.

### 10. Docker Compose chưa có TLS
Backend expose thẳng port 8080 HTTP; header `Strict-Transport-Security` (HSTS) gần như vô nghĩa nếu chưa từng có HTTPS.

→ Thêm Traefik/Nginx reverse proxy làm TLS termination (mkcert cho local, cert thật cho production).

---

## 🟢 Tính năng nên bổ sung

### 11. Chưa có phản ứng tự động (auto-response) khi phát hiện tấn công
Có bảng `blocked_ips` và trang Blocklist UI, nhưng có vẻ chỉ ghi nhận thủ công (Admin bấm block) — chưa tích hợp với `nftables`/`iptables` để thực sự chặn traffic ở tầng OS/firewall khi alert Critical được xác nhận.

→ Đây là mắt xích "respond" còn thiếu trong chuỗi detect → alert → **respond**.

### 12. Mở rộng thêm detection rules
Hiện có 6 rule: Port Scan, SYN Flood, Brute-force, ARP Spoof, DNS Tunneling, Z-score Volume Anomaly. Có thể thêm:
- ICMP flood / Smurf attack
- Slowloris (kết nối HTTP giữ chừng)
- TLS/JA3 fingerprint bất thường
- Beaconing detection (C2 callback theo chu kỳ đều đặn)
- Geo-IP anomaly (kết nối từ quốc gia lạ)

### 13. Nâng cấp anomaly detection
Z-score hiện chỉ theo 1 chiều (bytes/IP, dùng Welford's algorithm). Có thể:
- Multi-feature anomaly detection (Isolation Forest chạy offline theo batch)
- Thay Welford bằng EWMA để baseline thích nghi dần theo thời gian trong ngày, tránh false positive khi traffic pattern thay đổi tự nhiên (giờ cao điểm, cuối tuần...)

### 14. Bổ sung test coverage
README nói "18 tests" nhưng chưa thấy:
- Test cho `webhook.rs` (đặc biệt là test SSRF sau khi vá lỗ hổng ở mục 2)
- Test cho `rate_limit` middleware
- Test cho `reload_rules_from_db`

### 15. Thiết lập CI/CD
Repo chưa có `.github/workflows`. Nên thêm GitHub Actions chạy:
- `cargo test --workspace`
- `cargo clippy -- -D warnings`
- `cargo audit` (để khớp với tuyên bố "Clean Audit Check" trong README — hiện chưa được enforce tự động)

---

## Tóm tắt theo mức độ ưu tiên

| # | Hạng mục | Mức độ |
|---|---|---|
| 1 | Resolve conflict marker trong README | 🔴 Cao |
| 2 | Vá SSRF trong webhook dispatcher | 🔴 Cao |
| 3 | Rate limiter/throttler dùng Redis thay vì in-memory | 🔴 Cao |
| 4 | Parse thêm IPv6 trong capture engine | 🔴 Cao |
| 5 | Fix busy-loop trong `LiveCapture::next_event` | 🔴 Cao |
| 6 | Compression/retention policy cho hypertable | 🟡 Trung bình |
| 7 | Continuous aggregate cho dashboard | 🟡 Trung bình |
| 8 | Tách pipeline qua message broker | 🟡 Trung bình |
| 9 | Persist state của detection rules | 🟡 Trung bình |
| 10 | Thêm TLS termination trong Docker Compose | 🟡 Trung bình |
| 11 | Auto-block IP qua firewall khi alert Critical | 🟢 Thấp/Feature |
| 12 | Thêm detection rules mới | 🟢 Thấp/Feature |
| 13 | Nâng cấp anomaly detection (ML/EWMA) | 🟢 Thấp/Feature |
| 14 | Bổ sung test coverage | 🟢 Thấp/Feature |
| 15 | Thiết lập CI/CD | 🟢 Thấp/Feature |
