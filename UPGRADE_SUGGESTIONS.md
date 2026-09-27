# Gợi ý nâng cấp — Real-time Network Security Analytics & Alerting System (SecNet)

> Rà soát code thực tế tại repo [nguyenlinhit-cpu/Real-time-Network-Security-Analytics-Alerting-System](https://github.com/nguyenlinhit-cpu/Real-time-Network-Security-Analytics-Alerting-System).

---

## ✅ Đã giải quyết & hoàn thiện toàn diện

| # | Hạng mục | Trạng thái & Giải pháp |
|---|---|---|
| 1 | **Private key TLS trong git** | ✅ **Đã dọn sạch**: Xóa private key khỏi git tracking, thêm `deploy/nginx/certs/` vào `.gitignore`, tự động sinh TLS certificates cục bộ lúc container khởi động qua `entrypoint.sh`. |
| 2 | **SSRF trong webhook dispatcher** | ✅ **Đã vá kỹ**: Chặn private/loopback IP (IPv4 & IPv6), chặn redirect, kiểm tra HTTPS và có bộ unit test SSRF chuyên dụng. |
| 3 | **Rate limiter/throttler distributed** | ✅ **Đã thêm**: Redis distributed limiter sliding-window có fallback in-memory tự động khi Redis offline. |
| 4 | **Capture engine hỗ trợ IPv6** | ✅ **Đã hỗ trợ**: Hỗ trợ đầy đủ IPv4, IPv6, ICMPv6, TCP/UDP flag parsing. |
| 5 | **LiveCapture event flow** | ✅ **Đã tối ưu**: Dùng bounded MPSC channel + async receiver, loại bỏ busy-loop. |
| 6 | **Hypertable compression & retention** | ✅ **Đã có migration**: Nén sau 7 ngày, tự động xoá retention sau 30 ngày. |
| 7 | **Continuous aggregate cho dashboard** | ✅ **Đã có**: View `traffic_hourly_rollup` tối ưu hoá tốc độ truy vấn biểu đồ thời gian thực. |
| 8 | **Docker Compose TLS Nginx Proxy** | ✅ **Đã có**: Reverse proxy Nginx SSL/TLS, tự động redirect HTTP sang HTTPS. |
| 9 | **Detection rules nâng cao** | ✅ **Đã bổ sung**: C2 Beaconing, ICMP Flood, ARP Spoofing, Port Scan, SYN Flood, SSH Brute Force, DNS Tunneling, Z-Score Volume Anomaly. |
| 10 | **Test coverage & CI/CD** | ✅ **Đã hoàn thiện**: 28/28 test passed toàn workspace (unit tests, integration tests, detection tests), pipeline GitHub Actions đầy đủ. |
| 11 | **Bảo vệ `JWT_SECRET` production** | ✅ **Đã gia cố**: Backend từ chối khởi động (`panic!`) nếu `ENVIRONMENT=production` mà `JWT_SECRET` bị bỏ trống, dùng default `super_secret*`, hoặc ngắn hơn 32 ký tự. |
| 12 | **Phân biệt Access / Refresh Token** | ✅ **Đã phân tách**: Bổ sung claim `token_type` (`access` vs `refresh`) và `jti` UUID độc nhất. `auth_middleware` lập tức từ chối `401 Unauthorized` nếu dùng nhầm Refresh Token để gọi REST API. |
| 13 | **Cơ chế Logout & Thu hồi Token (Denylist)** | ✅ **Đã tích hợp**: Endpoint `POST /api/auth/logout`, lưu trữ `jti` bị thu hồi vào Redis (`secnet:revoked:<jti>`) kèm fallback bộ nhớ RAM. Tự động xoay vòng (rotate) và vô hiệu hoá Refresh Token cũ. Frontend gọi `api_logout()` khi đăng xuất. |
| 14 | **Account Lockout phân tán qua Redis** | ✅ **Đã chuyển sang Redis**: `failed_logins` đếm qua Redis key `secnet:lockout:<username>` với cửa sổ 15 phút, đồng bộ trên cụm nhiều backend instance (có fallback in-memory). |
| 15 | **Giới hạn Token qua Query String** | ✅ **Đã giới hạn**: Query param `?token=...` chỉ được chấp nhận duy nhất trên các route WebSocket (`/ws/alerts`, `/ws/traffic`), toàn bộ REST API bắt buộc gửi qua header `Authorization: Bearer <token>`. |
| 16 | **Persist State Detection Rules** | ✅ **Đã bền vững**: `capture-engine` tự động nạp state khi khởi động, định kỳ mỗi 30 giây snapshot trạng thái rules (bảng ARP IP↔MAC, counter, sliding windows) vào disk, lưu snapshot khi shutdown, và gắn Docker volume `capture_data:/data`. |
| 17 | **Auto-block Firewall (SOAR-lite)** | ✅ **Đã kích hoạt**: Tích hợp gọi trực tiếp `nftables` / `iptables`/`ip6tables` để chặn ngay attacker IP khi có Alert Critical, đồng thời tự động ghi nhận vào DB `blocked_ips` với thời hạn khoá 2 giờ. |
| 18 | **Container Healthchecks & Endpoints** | ✅ **Đã đồng bộ**: Bổ sung route `/health` và `/api/health`, cấu hình healthcheck cho `timescaledb`, `redis`, `backend`, `frontend` trong `docker-compose.yml` chống race-condition. |

---

## 🟢 Tính năng định hướng mở rộng (Roadmap tương lai)

1. **Session Management nâng cao**: Bảng quản lý danh sách session đang active cho phép người dùng xem thiết bị đã đăng nhập và Admin có thể thu hồi session từ xa.
2. **2FA / MFA (TOTP)**: Thêm xác thực hai bước qua Google Authenticator / Authy cho tài khoản Admin SOC.
3. **Threat Intelligence Feed**: Định kỳ tải danh sách IP xấu từ AbuseIPDB / Spamhaus / Feodo Tracker để đối soát tự động.
4. **Geo-IP Enrichment**: Tích hợp database MaxMind GeoLite2 để hiển thị cờ quốc gia, thành phố, ASN của địa chỉ IP nguồn trên Dashboard.
5. **Báo cáo định kỳ SOC (PDF / CSV)**: Lên lịch gửi email tổng kết vi phạm an ninh hàng ngày/hàng tuần cho quản trị viên.
