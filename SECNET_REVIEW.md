# Rà soát toàn diện SecNet — Lỗi cần fix, Chức năng bắt buộc & Chức năng có thể thêm

**Nội dung:** Phần A — 56 lỗi cần fix · Phần B — chức năng có thể thêm · Phần C — 55 chức năng bắt buộc kèm hiện trạng · Lộ trình.

> Repo: [nguyenlinhit-cpu/Real-time-Network-Security-Analytics-Alerting-System](https://github.com/nguyenlinhit-cpu/Real-time-Network-Security-Analytics-Alerting-System) — commit `734e38e` (27/09/2026).
> Cách rà: build thật toàn workspace, chạy test, chạy `cargo fmt --check` + `cargo clippy -D warnings` + `cargo audit` như CI; đọc toàn bộ handler backend, 8 detection rule, pipeline capture, **toàn bộ trang và component frontend**, docker-compose, Dockerfile, nginx. Frontend được type-check trên target native (môi trường rà chặn tải target WASM).

## Tóm tắt nhanh

- ✅ Build thành công, **28/28 test pass**; frontend biên dịch sạch.
- ❌ **CI fail 2/3 job**: `lint` (227 chỗ lệch format, ~12 cảnh báo clippy) và `security-audit` (`cargo audit` báo 2 lỗ hổng: `idna` qua `validator 0.18`, `rsa`).
- ❌ **Vấn đề lớn nhất: pipeline real-time chưa được nối end-to-end.** Capture engine phát hiện tấn công và ghi vào bảng `alerts`, nhưng backend không có gì đọc lại để đẩy lên WebSocket hay gửi Email/Telegram/Webhook. Traffic cũng không bao giờ được ghi vào `traffic_events`. Dashboard hiện chỉ đang hiển thị dữ liệu seed.
- ❌ **Có 2 lỗ hổng mức Critical:** ai cũng tự đăng ký được tài khoản **Admin**, và WebSocket không yêu cầu xác thực.
- ❌ `docker compose up` trên máy sạch **sẽ không chạy được** (healthcheck backend luôn fail, nginx TLS không có cert).
- ❌ **Frontend:** biểu đồ "Live throughput" hiển thị **số liệu giả**; trang Settings lưu cấu hình kênh sai key nên kênh tạo từ UI không bao giờ gửi được; không dùng refresh token nên sau 24h giao diện "chết" mà không tự đăng xuất.
- 📋 Trong 55 chức năng bắt buộc (Phần C): **5 đã chạy đúng, 22 có nhưng lỗi, 28 chưa có**.

---

# PHẦN A — LỖI CẦN FIX

## A1. 🔴 Chức năng lõi chưa chạy end-to-end

**1. Alert không bao giờ tới WebSocket / Email / Telegram / Webhook**
- `capture-engine` và `backend` là 2 process riêng; cầu nối duy nhất là `INSERT INTO alerts`.
- Trong backend **không có chỗ nào gửi vào `alert_broadcast` / `traffic_broadcast`** (chỉ có `subscribe()` trong `handlers/ws.rs`).
- `AlertDispatcher::dispatch()` **chỉ được gọi từ endpoint test kênh** (`handlers/notifications.rs:245`).
- → Toast, chuông báo động, Email/Telegram/Webhook chỉ hoạt động khi bấm "Test".
- **Cách sửa:** trigger Postgres `AFTER INSERT ON alerts` → `pg_notify('new_alert', ...)` + backend `PgListener` → broadcast + dispatch. Hoặc dùng Redis Streams (`RedisStreamBrokerSink` trong `pipeline.rs` đã viết sẵn nhưng chưa dùng).

**2. Không ghi traffic vào `traffic_events`**
- Chỉ có `INSERT` trong file seed. Capture engine chỉ chạy detection, không lưu event.
- → Trang Traffic, Device history, top talkers, continuous aggregate, compression đều chạy trên dữ liệu seed tĩnh; `/ws/traffic` không bao giờ phát.
- **Cách sửa:** batch insert (UNNEST/COPY) mỗi 100ms–1s trong capture engine, đồng thời publish lên bus cho backend.

**3. Phát hiện ARP Spoofing và DNS Tunneling chỉ chạy được với simulator**
- 2 detector đọc `MAC:` / `DNS:` trong trường `flags`, nhưng `live.rs` chỉ parse IPv4/IPv6 (bỏ qua frame ARP) và không bao giờ ghi MAC hay tên miền DNS vào `flags`.
- → Ở chế độ live, 2 rule này **không bao giờ kích hoạt**.
- **Cách sửa:** parse `EtherTypes::Arp` (`ArpPacket`), parse DNS query từ payload UDP/53.

**4. DNS Tunneling bị vô hiệu hoá sau khi load cấu hình từ DB**
- `update_config()` gán `entropy_threshold = threshold_value` = **50.0** (giá trị seed), trong khi Shannon entropy của một nhãn tên miền tối đa chỉ ≈ 5–6.
- → Điều kiện `entropy >= 50` không bao giờ đúng.

**5. Tên rule trong DB không khớp với code → 4/8 rule không cấu hình được từ UI**
| DB (seed) | Code `name()` |
|---|---|
| `SSH/RDP Brute-Force Detection` | `Brute-force Attack Detection` |
| `ARP Spoofing Detection` | `ARP Spoofing / Poisoning Detection` |
| *(không có)* | `ICMP Flood / Smurf Attack Detection` |
| *(không có)* | `C2 Beaconing / Periodic Callback Detection` |
- → Bật/tắt/sửa ngưỡng các rule này trên UI không có tác dụng; alert của chúng có `rule_id = NULL`.
- **Cách sửa:** khớp theo `id` hoặc thêm cột `key` cố định (vd `port_scan`), thêm migration seed cho 2 rule mới.

**6. Sửa rule trên UI không áp dụng real-time**
- `reload_rules_from_db()` chỉ gọi **1 lần lúc khởi động**. Cột `severity` và `condition_json` trong DB bị bỏ qua hoàn toàn (severity hard-code trong từng detector). Rule mới tạo từ UI không làm gì cả vì engine chỉ có 8 detector cố định.
- **Cách sửa:** `LISTEN rules_changed` hoặc reload định kỳ; đọc severity từ DB.

**7. Frontend mở WebSocket mới mỗi 5 giây, không đóng cái cũ**
- `ws/client.rs`: vòng `loop` tạo `WebSocket::new()` mỗi 5s mà không kiểm tra kết nối cũ còn sống; closure bị `forget()` → rò bộ nhớ.
- → Mỗi tab mở ~12 kết nối/phút cho mỗi stream. Khi pipeline (mục 1) được nối, mỗi alert sẽ hiện **lặp N lần**, chuông kêu chồng nhau, server cạn tài nguyên.
- **Cách sửa:** chỉ reconnect trong `onclose`, có exponential backoff, giữ 1 instance.

**8. CI fail ở 2/3 job**
- Job `lint`: `cargo fmt --all -- --check` báo 227 diff → chạy `cargo fmt --all`; `cargo clippy -- -D warnings` báo ~12 cảnh báo (5 `impl Default` có thể derive trong `common`, `strip_prefix` thủ công, `is_multiple_of`...) → chạy `cargo clippy --fix`.
- Job `security-audit`: `cargo audit` báo 2 lỗ hổng (xem mục 55).

## A2. 🔴 Lỗ hổng bảo mật nghiêm trọng

**9. Leo thang đặc quyền: ai cũng tự đăng ký được Admin**
- `/api/auth/register` public, nhận trường `role` từ client: `payload.role.unwrap_or(UserRole::Viewer)`. Trang Login còn có sẵn dropdown **"Admin — full configuration"**.
- **Cách sửa:** bỏ `role` khỏi `CreateUserDto` public (luôn là Viewer) hoặc tắt đăng ký mở; thêm API quản lý user chỉ cho Admin.

**10. WebSocket `/ws/alerts` và `/ws/traffic` không xác thực**
- `ws_routes` không nằm trong `protected_routes`, handler không kiểm tra token → ai kết nối được tới server đều nghe được luồng sự cố và traffic nội bộ. (Bản fix trước giới hạn `?token=` cho `/ws` nhưng route `/ws` thực ra không qua middleware.)
- **Cách sửa:** verify token (và `token_type == "access"`, chưa revoke) trong handler trước `on_upgrade`; frontend gửi `?token=`.

**11. Lộ secret của kênh thông báo cho mọi user**
- `GET /api/notifications/channels` không có RBAC và trả nguyên `config_json` (Telegram `bot_token`, webhook URL...). Kết hợp mục 9 → bất kỳ ai cũng đọc được.
- **Cách sửa:** chỉ Admin, mask secret khi trả về, mã hoá secret at-rest.

**12. Bypass rate limit & chống brute-force bằng header `X-Forwarded-For`**
- Backend lấy **giá trị đầu tiên** của XFF; nginx dùng `$proxy_add_x_forwarded_for` (nối thêm vào header client gửi) → giá trị đầu do attacker kiểm soát. Đổi XFF mỗi request = brute-force không giới hạn. Khi không có header, mọi client dùng chung bucket `127.0.0.1`. Port 8080 còn expose thẳng ra ngoài, bỏ qua nginx.
- **Cách sửa:** dùng `X-Real-IP` từ proxy tin cậy / lấy hop cuối / `ConnectInfo<SocketAddr>`; không publish port 8080.

**13. CORS thực tế là wildcard `*`**
- Code đọc `CORS_ALLOWED_ORIGINS` (số nhiều), nhưng `docker-compose.yml` và `.env.example` đặt `CORS_ALLOWED_ORIGIN` (số ít) → không tìm thấy → rơi vào nhánh `allow_origin(Any)`.

**14. JWT secret trong `.env.example` vượt qua được kiểm tra production**
- Giá trị `default_super_secret_jwt_key_32_bytes_long_change_in_production` không bắt đầu bằng `super_secret` và dài ≥ 32 → check trong `main.rs` cho qua. README hướng dẫn `cp .env.example .env`.
- **Cách sửa:** chặn mọi giá trị chứa `change_in_production`/`default`/`super_secret`, hoặc tự sinh secret ngẫu nhiên lần chạy đầu.

**15. Redis và Postgres expose ra host không có mật khẩu mạnh**
- Redis `6379` publish ra host, không `requirepass` → ai vào được host có thể xoá khoá thu hồi token, reset lockout/rate limit. Postgres `5432` publish với `postgres/postgres`.
- `SimpleRedisClient` không hỗ trợ `AUTH` (URL `redis://:pass@host` bị parse sai) → hiện không thể đặt mật khẩu.

**16. Logout không thu hồi refresh token**
- `logout` chỉ revoke `jti` của access token; refresh token (7 ngày) vẫn dùng được để lấy access token mới sau khi "đăng xuất".
- **Cách sửa:** gửi refresh token kèm request logout và revoke luôn, hoặc quản lý theo "token family".

**17. Auto-block có thể tự chặn hạ tầng của chính mình**
- Alert SYN Flood: `src_ip` = IP gửi gói SYN thứ N (ngẫu nhiên/giả mạo được). Alert ARP: `src_ip` = bất kỳ ai gửi gói tới IP đó. Không có allowlist cho gateway/DNS/server nội bộ, không có bước xác nhận.
- → Attacker giả mạo IP nguồn = gateway sẽ khiến hệ thống tự chặn gateway.
- **Cách sửa:** allowlist bắt buộc, chỉ auto-block với rule có độ tin cậy cao, yêu cầu phê duyệt (human-in-the-loop), block có TTL.

**18. Dò username qua thời gian phản hồi (timing attack)**
- User không tồn tại → trả lỗi ngay, không chạy Argon2 → nhanh hơn rõ rệt so với sai mật khẩu. README khẳng định chống user enumeration.
- **Cách sửa:** verify với một dummy hash khi không tìm thấy user.

**19. Khoá tài khoản bị lạm dụng để DoS**
- Lockout chỉ theo username → ai cũng khoá được tài khoản `admin` bằng 5 lần nhập sai.
- **Cách sửa:** khoá theo (username, IP), tăng dần độ trễ, CAPTCHA.

**20. CSV/Formula injection ở `/api/reports/export`**
- `title`/`description` chứa dữ liệu do attacker ảnh hưởng (vd tên miền DNS) nhưng không escape ký tự đầu `= + - @` → mở bằng Excel có thể chạy công thức. Endpoint cũng không có RBAC.

**21. SSRF qua DNS rebinding ở webhook**
- `validate_webhook_url()` resolve DNS để kiểm tra, sau đó `reqwest` resolve **lần nữa** khi gửi → domain đổi IP giữa 2 lần sẽ lọt. Host SMTP của kênh Email không được validate.
- **Cách sửa:** pin IP đã kiểm tra bằng `ClientBuilder::resolve()`.

**22. Telegram dùng `parse_mode: Markdown` không escape**
- Nội dung có `_ * [` sẽ làm Telegram trả 400 → mất tin nhắn âm thầm; attacker có thể chèn link vào cảnh báo gửi SOC.

**23. Các điểm yếu phụ về auth/web**
- Token thiếu `token_type` mặc định thành `"access"` (`#[serde(default)]`), token thiếu `jti` không thu hồi được → nên bắt buộc đủ claim.
- Access token sống 24h là dài với hệ thống SOC → nên 15 phút + refresh.
- JWT vẫn nằm trong `localStorage`; CSP cho phép `'unsafe-inline'` và Tailwind Play CDN (không dành cho production) → nếu có XSS thì mất token.
- `X-Request-ID` do client gửi được dùng nguyên → giả mạo log.
- `/metrics` public, mỗi lần gọi chạy 4 `COUNT(*)`.

## A3. 🟠 Độ chính xác phát hiện (false positive / false negative)

**24. Brute-force báo nhầm với phiên SSH bình thường**
- Đếm **mọi gói < 300 byte** tới port 22 → gõ phím trong SSH (gói nhỏ) cũng tính là "attempt"; vài giây là ra alert.
- **Cách sửa:** chỉ đếm kết nối mới (SYN không ACK) theo nguồn; tốt nhất tích hợp log xác thực (auth.log).

**25. Port Scan báo nhầm và bỏ sót**
- Đếm mọi gói chứ không chỉ SYN → server trả lời client qua nhiều cổng ephemeral bị coi là "quét cổng". Chỉ phát hiện quét dọc theo cặp (src, dst); bỏ sót quét ngang (1 cổng nhiều host) và quét phân tán.

**26. SYN Flood dùng ngưỡng tuyệt đối, không xét tỉ lệ half-open**
- Web server bận có thể vượt ngưỡng hợp lệ; alert Critical → auto-block client vô tội. Nên so SYN với SYN-ACK/ACK hoàn tất.

**27. Z-Score không đúng như mô tả**
- README: theo từng IP. Code: 1 cửa sổ toàn cục 100 gói gần nhất, đo **kích thước từng gói** → cứ có gói 1500 byte giữa các gói ACK 64 byte là "bất thường". Cooldown toàn cục che mất bất thường thật.
- **Cách sửa:** gom bytes theo host theo bucket thời gian, baseline riêng từng host.

**28. Beaconing báo nhầm với lưu lượng UDP định kỳ**
- Tính mọi gói UDP → VoIP/RTP, NTP, QUIC, DNS đều "tuần hoàn" → báo C2. Mô tả nói "external destination" nhưng code không kiểm tra.

**29. ARP detector lật trạng thái**
- Sau khi báo, ghi đè MAC tin cậy bằng MAC của attacker → khi MAC thật trả lời lại sẽ báo tiếp (flapping); DHCP cấp lại IP cũng ra alert Critical.

## A4. 🟠 Hiệu năng & độ ổn định

**30. Map trong bộ nhớ không bao giờ dọn**
- HashMap của mọi detector (theo IP/cặp IP), `rate_limiter`, `failed_logins`, `revoked_tokens`, cache throttler: chỉ thêm key, không xoá key. Với IP giả mạo (hoặc XFF giả, mục 12) → bộ nhớ tăng tới OOM.
- **Cách sửa:** cache có TTL (`moka`) hoặc job dọn định kỳ.

**31. Detector sụp đổ đúng lúc bị tấn công**
- SYN Flood / Port Scan lưu từng timestamp trong `Vec` và `retain` mỗi gói → O(n²) khi flood.
- **Cách sửa:** đếm theo bucket / ring buffer.

**32. Pipeline đơn luồng**
- Một `tokio::Mutex` bọc cả engine, giữ lock qua `alert_tx.send().await`; persister chạy `nft`/`iptables` + insert DB tuần tự → nghẽn ngược tới thread capture → rớt gói.
- **Cách sửa:** chia worker theo hash `src_ip`, xử lý batch.

**33. Redis client tự viết có nhiều rủi ro**
- 1 kết nối TCP dùng chung sau Mutex cho mọi request (mỗi API request ≥ 2 round-trip nối tiếp nhau). Không có timeout đọc → Redis treo thì **toàn bộ API treo**. `INCR` rồi `EXPIRE` không atomic → crash giữa chừng = key vĩnh viễn (khoá tài khoản/rate limit vĩnh viễn). Một số reply bị bỏ qua (`let _ = read_line`) có thể lệch protocol.
- **Cách sửa:** dùng crate `redis`/`fred` + pool (`deadpool`/`bb8`), `SET NX EX` + `INCR` hoặc Lua/MULTI.

**34. Query nặng**
- Dashboard tính tổng trên **toàn bộ** `traffic_events` mỗi lần load, không dùng `traffic_hourly_rollup`; "alert đang mở" đếm cả alert đã resolve.
- Lọc traffic dùng `host(src_ip) = $3` → không dùng được index; phân trang OFFSET sâu.
- `/api/alerts` cố định `LIMIT 100`, không lọc/phân trang phía server.

**35. Live capture lỗi âm thầm**
- Không có quyền raw socket → `LiveCapture::new()` vẫn trả `Ok`, thread thoát, engine ngồi im. Log ghi "Switching to simulation" nhưng không chuyển.
- File state ghi không atomic (crash giữa chừng → JSON hỏng → mất state); chỉ bắt SIGINT, còn `docker stop` gửi SIGTERM.

**36. Kênh thông báo luôn báo "thành công"**
- Mọi lỗi (non-2xx, lỗi mạng) đều trả `Ok(())` → audit log luôn `SUCCESS`, không retry/backoff/dead-letter.
- `test_channel` bỏ qua `id` (gửi tới **tất cả** kênh), và đi qua throttler → test lần 2 trong 60s bị chặn nhưng vẫn báo thành công.

**37. Email không dùng được với SMTP thật**
- `builder_dangerous` = SMTP plaintext (không TLS/STARTTLS, trái README); `username/password` luôn `None`; địa chỉ gửi hard-code → không gửi được qua Gmail/Office365/Mailtrap.

**38. Slack không hoạt động**
- Kênh Slack dùng `WebhookChannel` gửi nguyên JSON `Alert`, trong khi Slack yêu cầu `{"text": ...}` → bị từ chối.

## A5. 🟡 Triển khai & vận hành

**39. `docker compose up` không chạy trên máy sạch**
- Healthcheck backend dùng `wget`/`curl`, nhưng image `debian:bookworm-slim` **không có cả hai** → backend luôn unhealthy → `frontend`, `nginx-proxy`, `capture-engine` (đều `depends_on: service_healthy`) không bao giờ start.
- `nginx-proxy` tự sinh cert bằng `openssl`, nhưng `nginx:alpine` **không có openssl CLI** → bỏ qua âm thầm → nginx không start vì thiếu file cert (cert đã bị xoá khỏi repo).

**40. Capture engine trong Docker không giám sát/chặn được mạng thật**
- Chạy trên bridge network → chỉ sniff được veth của chính container. Không có `NET_RAW`/`NET_ADMIN`, image runtime không cài `nftables`/`iptables`, table/set `inet filter secnet_blocklist` chưa được tạo, và iptables trong container chỉ ảnh hưởng namespace của container.
- **Cách sửa:** `network_mode: host`, `cap_add: [NET_RAW, NET_ADMIN]`, cài nftables, script bootstrap table/set.

**41. Blocklist không nhất quán giữa DB và firewall**
- `blocked_until` không được thực thi (không có job hết hạn) → rule firewall tồn tại vĩnh viễn. Block/unblock thủ công trên UI không chạm tới firewall. Block lại IP đã có → vi phạm UNIQUE → lỗi 500.

**42. Migration không áp dụng cho DB đang chạy**
- Migration chỉ chạy qua `docker-entrypoint-initdb.d` (lần init đầu); backend không gọi `sqlx::migrate!` → migration `0012` không bao giờ được áp vào volume đã có dữ liệu.

**43. Build phụ thuộc mạng**
- `utoipa-swagger-ui` tải Swagger UI từ GitHub trong `build.rs` → build lỗi khi offline/sau proxy (đã gặp khi rà). Bật feature `vendored` của `utoipa-swagger-ui` 7.1.

**44. Vệ sinh repo & cấu hình**
- Thư mục `crates/frontend/dist/` (file build `.wasm`, `.js`) bị commit vào git.
- Image `timescale/timescaledb:latest-pg15` không pin version.
- Capture engine chạy root cả khi ở chế độ simulation; không có `REDIS_URL`.
- `DEMO_SCENARIO` và `SIMULATION_PACKETS_PER_SEC` bị đọc rồi bỏ qua (vòng lặp cố định 5 kịch bản, sleep 50ms ≈ 20 gói/s); kịch bản `volume_spike` không bao giờ chạy trong demo.

**45. README lỗi thời**
- Vẫn ghi 6 rule / 18 test (thực tế 8 rule / 28 test), Z-score "theo từng IP", SMTP có TLS, Telegram MarkdownV2 — đều không đúng với code. Chưa nhắc Redis, nginx TLS, `ENVIRONMENT=production`. Có 7 link dạng `file:///home/linh/...` bị hỏng trên GitHub.

## A6. 🟠 Frontend (Leptos)

**46. Frontend không dùng refresh token và không xử lý hết hạn đăng nhập**
- Login/Register chỉ lưu access token, **bỏ luôn `refresh_token`**; không có chỗ nào gọi `/api/auth/refresh`; không bắt lỗi 401.
- App coi là "đã đăng nhập" chỉ vì còn token trong `localStorage` → sau 24h giao diện vẫn hiện như bình thường nhưng mọi dữ liệu trống/lỗi, không tự chuyển về trang Login. Cơ chế refresh + rotation vừa làm ở backend không được dùng.
- **Cách sửa:** lưu refresh token, bọc request: gặp 401 → gọi refresh → thử lại 1 lần → thất bại thì đăng xuất.

**47. Biểu đồ "Live network throughput" hiển thị số liệu giả**
- `components/traffic_chart.rs` khởi tạo mảng cứng `[120, 180, 140, 220, 310, 280, 350, 420, 390, 500]`, mỗi lần cập nhật đẩy vào `(tổng_bytes % 600 + 100)` — không phải lưu lượng thật.
- Ô "Current throughput … B/s" thực ra là **tổng byte cộng dồn** từ lúc mở trang (chỉ tăng, không chia theo giây).
- → Với đồ án, đây là điểm dễ bị hội đồng bắt lỗi nhất: số liệu trình bày như dữ liệu thật nhưng là số bịa.
- **Cách sửa:** tính bytes/giây theo cửa sổ trượt từ luồng traffic, hoặc lấy từ continuous aggregate; bỏ dữ liệu khởi tạo cứng.

**48. Trang Settings không cấu hình được kênh thông báo**
- Form chỉ có **1 ô URL cho mọi loại kênh** và lưu với key `"url"`, trong khi backend đọc `endpoint_url` (Webhook), `webhook_url` (Slack), `bot_token`/`chat_id` (Telegram), `smtp_host`/`smtp_port`/`to_email` (Email).
- → Kênh tạo từ UI **không bao giờ gửi được**; Email và Telegram không có ô nhập thông tin. Vì key sai nên bước kiểm tra SSRF lúc tạo kênh cũng bị bỏ qua.
- Secret ký hard-code `"secnet_sign_key"` cho mọi kênh (và không được dùng ở đâu); `min_severity` cố định High; nhãn "ACTIVE" luôn hiện dù kênh đã tắt; không có chức năng sửa kênh; `config_json` hiển thị thô (lộ secret).
- **Cách sửa:** form riêng theo từng loại kênh, dùng đúng tên key, dùng chung struct cấu hình giữa frontend và backend (crate `common`).

**49. Nút thao tác hiện sai quyền, lỗi bị nuốt im lặng**
- Viewer vẫn thấy nút Acknowledge/Resolve; Analyst thấy trang Blocklist với nút chặn/gỡ IP, nhưng API chỉ cho Admin → bấm không có phản hồi (lỗi 403 bị bỏ qua).
- Xử lý alert, chặn IP, tạo/sửa rule, export CSV đều chỉ xử lý nhánh `if let Ok(...)` hoặc `let _ =` → người dùng tưởng đã chặn IP nhưng thực tế chưa.
- **Cách sửa:** ẩn/khoá nút theo role; hiện toast lỗi cho mọi thao tác thất bại.

**50. Giao diện không tự làm mới dữ liệu**
- Alerts, traffic, số liệu dashboard chỉ tải **1 lần** khi đăng nhập, không polling. Vì WebSocket chưa có dữ liệu (mục 1), giao diện đứng yên cho tới khi F5.

**51. Lọc/tìm kiếm chỉ trên dữ liệu đã tải về**
- Trang Alerts lọc trên 100 alert đầu tiên; trang Traffic lọc trên 50 event gần nhất — dù API `/api/traffic` đã hỗ trợ lọc theo thời gian, IP, protocol.

**52. Không có routing theo URL**
- `leptos_router` được khai báo trong `Cargo.toml` nhưng không dùng; điều hướng bằng signal `active_tab` → F5 luôn quay về Dashboard, nút Back của trình duyệt không hoạt động, không gửi được link tới 1 alert cụ thể.

**53. Dùng `js_sys::eval` để tải CSV và phát âm thanh**
- Nội dung CSV (có phần dữ liệu do attacker ảnh hưởng) được nhúng vào chuỗi JavaScript rồi `eval`. Hiện đã escape nhưng đây là pattern rủi ro, và buộc CSP phải cho phép `unsafe-eval` (nếu áp CSP chặt cho frontend thì 2 chức năng này sẽ hỏng).
- **Cách sửa:** `web_sys::Blob` + `Url::create_object_url` cho CSV; `web_sys::AudioContext` cho âm thanh.

**54. Thiếu thao tác quản trị trên UI**
- Không có nút xoá rule (API có), không sửa kênh thông báo, không đánh dấu thiết bị tin cậy, không hiển thị thời hạn chặn IP; thời hạn chặn cố định 24h.

## A7. 🟠 Thư viện phụ thuộc & kiểm thử

**55. `cargo audit` báo 2 lỗ hổng → job `security-audit` trên CI sẽ fail**
| Crate | Mã | Vấn đề | Đến từ | Cách xử lý |
|---|---|---|---|---|
| `idna 0.5.0` | RUSTSEC-2024-0421 | Chấp nhận nhãn Punycode không hợp lệ (ảnh hưởng validate email/domain) | `validator 0.18` | Nâng `validator` lên ≥ 0.19 (dùng `idna 1.x`) |
| `rsa 0.9.10` | RUSTSEC-2023-0071 (5.9 Medium) | Marvin Attack — lộ khoá qua timing | `sqlx-mysql` (chỉ có trong `Cargo.lock`, không được biên dịch vì chỉ dùng Postgres) | Không có bản sửa; thêm `.cargo/audit.toml` bỏ qua mã này kèm lý do |
- Thêm 3 cảnh báo thư viện không còn được bảo trì: `paste` và `proc-macro-error2` (qua Leptos 0.7), `proc-macro-error` (qua `utoipa 4` và `validator 0.18`) → nâng `utoipa` lên 5.x, cân nhắc Leptos 0.8.

**56. Test gọi Internet thật và đang "khoá" hành vi sai**
- `alert_multichannel_simulation_test` gửi request thật tới `93.184.216.34` (example.com) và `api.telegram.org` → test chậm (~5s), phụ thuộc mạng, fail trong môi trường chặn Internet.
- Các test này **assert `is_ok()` khi gửi thất bại** — tức là đang khẳng định lỗi ở mục 36 (nuốt lỗi) là đúng. Khi sửa mục 36, các test này sẽ fail.
- **Cách sửa:** dùng mock server (`wiremock`), assert gửi thất bại trả `Err` và có retry.

> **Giới hạn của lần rà:** không build được bản WASM vì môi trường rà chặn tải target `wasm32-unknown-unknown`. Frontend đã được type-check trên target native: biên dịch sạch, crate `frontend` không có cảnh báo clippy riêng. `trunk build` chưa được kiểm chứng.

---

# PHẦN B — CHỨC NĂNG CÓ THỂ THÊM

## B1. Hoàn thiện lõi IDS
- **Event bus** (Redis Streams / NATS / Kafka) giữa capture và backend; backend consume → WebSocket + dispatcher.
- **Flow aggregation** kiểu NetFlow (5-tuple, thời điểm đầu/cuối, bytes, packets) thay vì lưu từng gói → giảm dung lượng hàng trăm lần.
- **Parser giao thức:** ARP, DHCP, DNS (query, rcode, NXDOMAIN), HTTP (Host, URI, User-Agent), TLS (SNI, JA3/JA4), SSH banner.
- **Nguồn dữ liệu ngoài:** collector NetFlow/IPFIX/sFlow, import Zeek/Suricata EVE JSON, syslog (log xác thực cho brute-force chính xác), upload PCAP để phân tích offline.
- **Capture hiệu năng cao:** BPF filter, nhiều interface, AF_PACKET v3 / eBPF-XDP.
- **Rule engine tổng quát:** rule định nghĩa trong DB bằng DSL (điều kiện, ngưỡng, group_by, cửa sổ), hỗ trợ **Sigma**, tương thích signature Suricata/Snort, YARA cho payload.
- **Hot reload rule** qua `LISTEN/NOTIFY`.
- **Allowlist / suppression** theo IP, subnet, port, từng rule; cửa sổ bảo trì (maintenance window).

## B2. Rule phát hiện mới
- Quét ngang, quét phân tán, UDP scan, stealth scan (FIN/NULL/Xmas).
- DNS: NXDOMAIN flood, tên miền do DGA sinh, DNS amplification, bản ghi TXT bất thường.
- **Lateral movement:** host nội bộ kết nối nhiều host nội bộ qua SMB/RDP/WinRM/SSH.
- **Exfiltration:** lượng upload ra ngoài vượt baseline, upload tới đích hiếm gặp.
- Thiết bị lạ xuất hiện, rogue DHCP, MAC flooding, dịch vụ mới mở cổng.
- Kết nối tới IP/domain độc hại (threat intel), Tor exit node.
- Bất thường TLS (cert tự ký/hết hạn, JA3 hiếm), credential plaintext (FTP/Telnet/HTTP Basic).
- UDP flood, amplification (NTP/memcached/SSDP), HTTP flood/Slowloris.
- Geo-anomaly: kết nối từ quốc gia chưa từng thấy.
- **ML/thống kê:** baseline theo từng host có tính mùa vụ (giờ trong ngày, ngày trong tuần), EWMA, Isolation Forest/autoencoder huấn luyện offline.

## B3. Threat intelligence & làm giàu dữ liệu
- Feed: AbuseIPDB, Spamhaus DROP, FireHOL, Feodo Tracker, URLhaus; tích hợp MISP/OpenCTI qua STIX/TAXII.
- GeoIP/ASN (MaxMind GeoLite2), reverse DNS, WHOIS.
- Ngữ cảnh tài sản: chủ sở hữu, mức quan trọng, tag → tính **risk score** cho alert.
- Gắn **MITRE ATT&CK** (tactic/technique) cho từng rule và alert.

## B4. Quy trình SOC / quản lý sự cố
- Gom alert thành **incident/case** (tương quan theo nguồn/thời gian), giao việc, bình luận, timeline, đính kèm bằng chứng.
- Workflow trạng thái, SLA (MTTA/MTTR), chính sách leo thang, lịch trực.
- Deduplicate kèm bộ đếm ("đã thấy 1.234 lần"), snooze, đánh dấu false positive để tinh chỉnh ngưỡng.
- Trang **Threat Hunting**: ngôn ngữ truy vấn, lưu truy vấn, pivot theo IP/host.
- **Ghi PCAP quanh thời điểm alert** (ring buffer N giây trước/sau) phục vụ điều tra.
- Ghi chú, tag, thao tác hàng loạt.

## B5. Phản ứng tự động (SOAR-lite)
- **Playbook:** điều kiện → hành động (chặn IP, gửi thông báo, tạo ticket, cô lập host).
- Tích hợp firewall: nftables, pfSense/OPNsense, MikroTik, FortiGate, security group trên cloud.
- Bước phê duyệt trước khi chặn, block có TTL tự hết hạn, allowlist bảo vệ hạ tầng.
- Ticket/on-call: Jira, ServiceNow, GLPI, PagerDuty, Opsgenie.
- Kênh chat đúng định dạng: Slack, Microsoft Teams, Discord, Zalo OA.
- Webhook ký **HMAC** để bên nhận xác thực; retry có backoff; dead-letter queue.

## B6. Người dùng & xác thực
- Trang **quản lý user** cho Admin (tạo, khoá, đổi role, reset mật khẩu).
- 2FA (TOTP / WebAuthn), SSO (OIDC/SAML), LDAP/Active Directory.
- Quản lý phiên (xem/thu hồi phiên đang hoạt động), chính sách mật khẩu, quên mật khẩu qua email.
- Phân quyền chi tiết hơn 3 role; **API key / service account** cho tích hợp.
- Multi-tenant / multi-site (mỗi site một sensor).
- Trang xem **audit log** có lọc/export; audit log chống sửa (hash chain).

## B7. Dashboard & trải nghiệm
- Bộ chọn khoảng thời gian, drill-down, tuỳ chỉnh tần suất refresh.
- **Bản đồ quan hệ mạng** (ai nói chuyện với ai), Sankey, bản đồ địa lý.
- Heatmap giờ × ngày, phân bố giao thức theo thời gian (dùng continuous aggregate).
- Trang chi tiết alert: traffic liên quan, timeline, ATT&CK, gợi ý xử lý.
- Browser Notification API; tuỳ chỉnh âm thanh theo severity.
- Dashboard/widget tự sắp xếp và lưu.
- Đa ngôn ngữ (VI/EN); Tailwind build-time thay CDN.

## B8. Báo cáo & tuân thủ
- Báo cáo định kỳ tự động (ngày/tuần, PDF/HTML qua email): top attacker, top mục tiêu, MTTR, xu hướng.
- Export CSV an toàn, JSON, PDF, STIX.
- Ánh xạ yêu cầu tuân thủ (ISO 27001, PCI DSS về log), cấu hình thời gian lưu trữ trên UI.

## B9. Giám sát chính hệ thống & vận hành
- Metrics Prometheus thật (crate `metrics`): packets/s, tỉ lệ rớt gói, độ trễ xử lý rule, độ sâu hàng đợi, alert theo rule, độ trễ ghi DB; kèm dashboard Grafana.
- OpenTelemetry tracing xuyên suốt capture → backend.
- Trang **sức khoẻ sensor** (heartbeat, rớt gói, version).
- Log JSON có cấu trúc; đẩy log về Loki/ELK.
- Validate cấu hình khi khởi động (fail fast).
- Backup DB, HA (Postgres replication, Redis Sentinel).
- Helm chart / manifest Kubernetes, systemd unit cho sensor chạy bare-metal.
- TLS thật bằng Let's Encrypt (Caddy/certbot).

## B10. Chất lượng & kiểm thử
- Integration test với Postgres/Redis thật (testcontainers); **test end-to-end**: simulator tấn công → alert xuất hiện trên WebSocket.
- **Replay PCAP từ dataset chuẩn** (CIC-IDS2017, UNSW-NB15) để đo precision/recall/tỉ lệ false positive từng rule — rất giá trị cho phần đánh giá của đồ án.
- Benchmark (`criterion`) đo throughput packets/s; fuzz parser gói tin (`cargo-fuzz`).
- Test frontend (`wasm-bindgen-test`, Playwright).
- Dependabot/Renovate, `cargo-deny` (license + advisory), SBOM, quét image (Trivy), ký image.
- Bổ sung endpoint `/api/reports/export` vào OpenAPI; version hoá API (`/api/v1`).

## B11. Kiến trúc mở rộng
- Nhiều sensor gửi về trung tâm (đăng ký sensor, mTLS).
- Backend stateless scale ngang: fan-out WebSocket qua Redis pub/sub (hiện `broadcast` channel nằm trong process nên mỗi instance chỉ phục vụ client của riêng nó).
- Chia detection theo hash `src_ip` cho nhiều worker/node.
- Lưu trữ lạnh (S3/Parquet) cho dữ liệu cũ, tiered storage của TimescaleDB.

## B12. Hướng mở rộng khác
- **IPv6:** phát hiện giả mạo Router Advertisement, NDP spoofing (tương đương ARP spoofing trên IPv6).
- **Đóng gói:** đọc tag VLAN (802.1Q), bóc tunnel GRE/VXLAN để thấy traffic bên trong.
- **Wi‑Fi:** phát hiện deauth attack, rogue AP, evil twin.
- **Traffic mã hoá:** phân tích dựa trên đặc trưng flow (kích thước, nhịp gói) mà không cần giải mã.
- **Trích file** truyền qua HTTP/SMB, tra hash trên VirusTotal.
- **Deception:** honeypot / honeytoken (canary) — mọi kết nối tới đều đáng nghi, gần như không báo nhầm.
- **Tương quan lỗ hổng:** lấy kết quả Nmap/OpenVAS để ưu tiên alert nhắm vào máy có lỗ hổng thật.
- **Giám sát băng thông** (không chỉ bảo mật): ứng dụng/user dùng nhiều nhất.
- **AI hỗ trợ:** LLM tóm tắt sự cố, giải thích alert bằng tiếng Việt, gợi ý xử lý; hỏi dữ liệu bằng ngôn ngữ tự nhiên.
- **Rule as code:** import/export rule YAML/JSON, quản lý bằng Git.
- **Plugin** detector tuỳ chỉnh (ví dụ WASM plugin).
- **Sao lưu/khôi phục** toàn bộ cấu hình.
- **Cập nhật threat intel offline** cho môi trường không có Internet.
- **Tuân thủ Việt Nam:** che dữ liệu cá nhân trong log/alert theo Nghị định 13/2023/NĐ-CP.
- **Ứng dụng di động / push notification** cho người trực.

---

# PHẦN C — CHỨC NĂNG BẮT BUỘC PHẢI CÓ

**Tiêu chí "bắt buộc":** thiếu chức năng đó thì hệ thống (1) không làm được đúng việc nó tuyên bố — phát hiện và cảnh báo theo thời gian thực, (2) không an toàn để triển khai, hoặc (3) không chứng minh được là hoạt động đúng. Các chức năng ở Phần B không nằm trong bảng này là "nên có", không bắt buộc.

**Hiện trạng** (theo code commit `734e38e`): ✅ đã có và chạy đúng · ⚠️ có nhưng lỗi hoặc thiếu một phần · ❌ chưa có. Cột "Mục" trỏ tới lỗi tương ứng ở Phần A.

## C1. Thu thập dữ liệu

| # | Chức năng bắt buộc | Vì sao bắt buộc | Hiện trạng | Mục |
|---|---|---|---|---|
| 1 | Bắt gói trên interface thật của máy/mạng cần giám sát | Không có dữ liệu thật thì mọi thứ phía sau vô nghĩa | ⚠️ Có code, nhưng trong Docker chỉ thấy traffic của chính container | 40 |
| 2 | Parse IPv4/IPv6, TCP/UDP/ICMP | Nền tảng cho mọi rule | ✅ | — |
| 3 | Parse ARP và DNS | Rule ARP Spoofing và DNS Tunneling cần | ❌ | 3 |
| 4 | Loại trừ traffic quản trị của chính hệ thống (DB, Redis, API) | Tránh tự phát hiện chính mình và vòng lặp ghi dữ liệu | ❌ | — |
| 5 | Lưu traffic (dạng flow) vào TimescaleDB theo batch | Dashboard, điều tra, báo cáo đều dựa vào đây | ❌ | 2 |
| 6 | Kênh truyền sự kiện capture → backend | Để alert/traffic tới được UI và kênh thông báo | ❌ | 1 |
| 7 | Hàng đợi có giới hạn + đo tỉ lệ rớt gói | IDS phải biết khi nào nó đang "mù" | ⚠️ Có hàng đợi giới hạn, không đo rớt gói | 32 |
| 8 | Giới hạn bộ nhớ trạng thái (TTL, dọn key) | Không bị attacker làm tràn RAM | ❌ | 30, 31 |

## C2. Phát hiện

| # | Chức năng bắt buộc | Vì sao bắt buộc | Hiện trạng | Mục |
|---|---|---|---|---|
| 9 | Các rule cơ bản chạy đúng trên dữ liệu thật (Port Scan, SYN Flood, Brute-force, ARP, DNS Tunneling, Volume Anomaly) | Là chức năng chính của hệ thống | ⚠️ Có nhưng báo nhầm nhiều, 2 rule không chạy ở chế độ live, DNS bị vô hiệu | 3, 4, 24–29 |
| 10 | Sửa rule trên UI được áp dụng ngay, kể cả severity | README tuyên bố "điều chỉnh theo thời gian thực" | ❌ | 5, 6 |
| 11 | Allowlist / suppression theo IP, subnet, rule | Không có thì analyst bị ngập báo nhầm và bỏ qua cảnh báo thật | ❌ | 17 |
| 12 | Gộp/giảm alert trùng (dedup, cooldown) | Chống "bão cảnh báo" khi bị DDoS | ⚠️ Có throttler nhưng nằm ở dispatcher chưa được nối | 1 |
| 13 | Đo độ chính xác từng rule (replay PCAP / dataset chuẩn) | Không đo thì không chứng minh được hệ thống phát hiện đúng | ❌ | B10 |

## C3. Cảnh báo

| # | Chức năng bắt buộc | Vì sao bắt buộc | Hiện trạng | Mục |
|---|---|---|---|---|
| 14 | Lưu alert vào DB | Làm bằng chứng, điều tra, báo cáo | ✅ | — |
| 15 | Đẩy alert real-time lên dashboard | Tên hệ thống là "Real-time" | ❌ | 1, 7 |
| 16 | Ít nhất 1 kênh ngoài gửi được thật (Email có TLS + đăng nhập, hoặc Telegram) | Người trực không ngồi nhìn dashboard 24/7 | ⚠️ Telegram có code; Email không TLS, không đăng nhập; cả hai chưa được nối | 1, 22, 37 |
| 17 | Retry khi gửi lỗi + ghi đúng trạng thái gửi | Không được mất cảnh báo âm thầm | ❌ | 36 |
| 18 | Cấu hình đầy đủ từng loại kênh (Email, Telegram, Webhook) từ giao diện | Admin không thể sửa DB bằng tay để thêm kênh | ❌ Form lưu sai key, thiếu ô nhập | 48 |

## C4. Điều tra & xử lý sự cố

| # | Chức năng bắt buộc | Vì sao bắt buộc | Hiện trạng | Mục |
|---|---|---|---|---|
| 19 | Danh sách alert lọc + phân trang phía server | Khi có hàng nghìn alert, `LIMIT 100` là không dùng được | ❌ | 34 |
| 20 | Trang chi tiết alert kèm traffic liên quan | Analyst cần ngữ cảnh để quyết định | ❌ | — |
| 21 | Quy trình Acknowledge → Resolve, ghi người xử lý | Phân công, tránh 2 người xử lý 1 sự cố | ✅ | — |
| 22 | Ghi audit log | Truy vết hành động quản trị | ✅ | — |
| 23 | Trang xem audit log cho Admin | Có ghi mà không xem được thì không có tác dụng | ❌ | — |
| 24 | Chặn IP: DB và firewall đồng bộ, tự hết hạn, allowlist hạ tầng, có bước phê duyệt | Chặn sai = tự gây sự cố cho mạng của mình | ⚠️ Có ghi DB và gọi lệnh firewall, nhưng không đồng bộ, không hết hạn, không allowlist | 17, 40, 41 |
| 25 | Xuất báo cáo an toàn | Báo cáo cho quản lý | ⚠️ Có CSV nhưng dính formula injection, không RBAC | 20 |
| 26 | Giao diện báo lỗi rõ ràng và chỉ hiện thao tác đúng quyền | Người dùng tưởng đã chặn IP/xử lý alert nhưng thực tế thất bại | ❌ | 49 |

## C5. Bảo mật của chính hệ thống

| # | Chức năng bắt buộc | Vì sao bắt buộc | Hiện trạng | Mục |
|---|---|---|---|---|
| 27 | Không cho tự đăng ký role cao; Admin quản lý user (tạo, khoá, đổi role) | Hệ thống bảo mật mà ai cũng thành Admin được | ❌ | 9 |
| 28 | Xác thực mọi endpoint, kể cả WebSocket | Luồng alert/traffic là dữ liệu nhạy cảm | ⚠️ REST có, WebSocket không | 10 |
| 29 | RBAC cho dữ liệu nhạy cảm + mã hoá secret kênh thông báo | Tránh lộ bot token, mật khẩu SMTP | ❌ | 11 |
| 30 | Rate limit và khoá tài khoản dựa trên IP tin cậy | Chống brute-force vào chính hệ thống | ⚠️ Có nhưng bypass được | 12, 19 |
| 31 | Thu hồi token khi logout (cả refresh token), access token ngắn hạn | Mất token không bị dùng lại | ⚠️ Chỉ thu hồi access token, token sống 24h | 16, 23 |
| 32 | Frontend tự gia hạn phiên bằng refresh token, tự đăng xuất khi hết hạn | Access token ngắn hạn chỉ dùng được khi có cơ chế này | ❌ | 46 |
| 33 | 2FA cho tài khoản Admin | Admin điều khiển được firewall | ❌ | B6 |
| 34 | Không dùng secret mặc định; Redis/Postgres có mật khẩu và không public | Cấu hình mặc định phải an toàn | ⚠️ Có check JWT nhưng bypass được; Redis/Postgres public | 14, 15 |
| 35 | CORS whitelist hoạt động đúng | Chặn web lạ gọi API | ⚠️ Thực tế đang là `*` | 13 |
| 36 | HTTPS hoạt động thật | Token và dữ liệu không đi dạng plaintext | ⚠️ Có nginx TLS nhưng không khởi động được | 39 |
| 37 | Không dùng thư viện có lỗ hổng đã công bố | Sản phẩm bảo mật không được tự mang lỗ hổng | ⚠️ 2 lỗ hổng, 3 thư viện ngừng bảo trì | 55 |

## C6. Vận hành

| # | Chức năng bắt buộc | Vì sao bắt buộc | Hiện trạng | Mục |
|---|---|---|---|---|
| 38 | Triển khai 1 lệnh chạy được trên máy sạch | Người khác (và hội đồng) phải chạy được | ❌ | 39 |
| 39 | Migration tự chạy khi khởi động | Nâng cấp không phải xoá dữ liệu | ❌ | 42 |
| 40 | Theo dõi sức khoẻ sensor (heartbeat, cảnh báo khi sensor ngừng) | IDS chết âm thầm còn nguy hiểm hơn không có IDS | ❌ | 35 |
| 41 | Metrics nội bộ: packets/s, rớt gói, độ sâu hàng đợi, độ trễ rule | Biết hệ thống có theo kịp traffic không | ⚠️ Có `/metrics` nhưng chỉ đếm số bản ghi DB | — |
| 42 | Retention + compression dữ liệu | Không đầy ổ cứng | ✅ (chưa áp được vào DB cũ) | 42 |
| 43 | Sao lưu DB | Mất DB = mất toàn bộ bằng chứng | ❌ | B9 |
| 44 | Tắt an toàn (bắt SIGTERM) + ghi state atomic | Không mất/hỏng trạng thái khi `docker stop` | ⚠️ | 35 |
| 45 | Log có cấu trúc (JSON) | Tìm kiếm, đẩy về hệ thống log tập trung | ⚠️ Có `tracing` nhưng log dạng text | — |

## C7. Chất lượng & tài liệu

| # | Chức năng bắt buộc | Vì sao bắt buộc | Hiện trạng | Mục |
|---|---|---|---|---|
| 46 | CI xanh: test, fmt, clippy, audit | Mọi thay đổi được kiểm tra tự động | ⚠️ Test pass; lint và audit fail | 8, 55 |
| 47 | Test end-to-end: tấn công giả lập → alert xuất hiện trên WebSocket và kênh thông báo | Kiểm chứng đúng luồng chính — chính là luồng đang bị đứt | ❌ | 1 |
| 48 | Test không phụ thuộc Internet, kiểm tra đúng hành vi (dùng mock) | Test phải ổn định và bắt được lỗi thật | ⚠️ Có test nhưng gọi mạng thật và assert sai | 56 |
| 49 | Benchmark throughput (packets/s tối đa trước khi rớt gói) | Biết giới hạn thật của hệ thống | ❌ | 32 |
| 50 | Build không phụ thuộc mạng | Build lại được trong CI/Docker bất kỳ lúc nào | ⚠️ | 43 |
| 51 | README/tài liệu khớp với code | Người dùng, hội đồng đọc README để đánh giá | ⚠️ Nhiều chỗ sai | 45 |

## C8. Bắt buộc riêng cho demo / bảo vệ đồ án

| # | Chức năng bắt buộc | Vì sao bắt buộc | Hiện trạng | Mục |
|---|---|---|---|---|
| 52 | Chọn được từng kịch bản tấn công để demo (biến môi trường hoặc nút trên UI) | README hướng dẫn `DEMO_SCENARIO=port_scan` nhưng code bỏ qua | ⚠️ | 44 |
| 53 | Luồng demo hoàn chỉnh: tấn công → alert trên UI → chuông → Telegram/Email | Đây là thứ hội đồng sẽ xem | ❌ | 1, 7 |
| 54 | Dashboard chỉ hiển thị số liệu thật | Số liệu bịa trên màn hình demo làm mất uy tín toàn bộ đồ án | ❌ Biểu đồ throughput là số giả | 47 |
| 55 | Số liệu đánh giá: precision/recall, tỉ lệ báo nhầm, throughput | Phần "Đánh giá kết quả" của báo cáo đồ án | ❌ | 13, 44 |

## Tổng kết Phần C

| Hiện trạng | Số chức năng |
|---|---|
| ✅ Đã có và chạy đúng | 5 / 55 |
| ⚠️ Có nhưng lỗi hoặc thiếu một phần | 22 / 55 |
| ❌ Chưa có | 28 / 55 |

---

# Đề xuất thứ tự làm

| Giai đoạn | Việc | Mục |
|---|---|---|
| **1. Cho hệ thống chạy được** | Sửa healthcheck + cert nginx, nối pipeline alert/traffic (LISTEN/NOTIFY), sửa WS client reconnect, khớp tên rule, sửa ngưỡng DNS, biểu đồ dùng số liệu thật, sửa form cấu hình kênh, `cargo fmt` + `clippy` | 1–8, 39, 42, 47, 48 |
| **2. Vá bảo mật Critical/High** | Chặn tự đăng ký Admin, xác thực WebSocket, ẩn secret kênh thông báo, sửa XFF, CORS, JWT secret, Redis/Postgres không expose, logout thu hồi refresh token, frontend dùng refresh token, nâng `validator` | 9–17, 46, 55 |
| **3. Giảm false positive** | Viết lại brute-force, port scan, z-score, beaconing, ARP; allowlist trước khi bật auto-block | 17, 24–29 |
| **4. Ổn định & hiệu năng** | TTL cache, bucket counter, crate Redis chuẩn + pool, dùng rollup cho dashboard, retry kênh thông báo, sửa Email/Slack, viết lại test bằng mock | 30–38, 56 |
| **4b. Hoàn thiện giao diện** | Ẩn nút theo quyền + báo lỗi, tự làm mới dữ liệu, lọc phía server, routing theo URL, bỏ `eval` | 49–54 |
| **5. Hoàn tất chức năng bắt buộc còn thiếu** | Allowlist, parse ARP/DNS, trang chi tiết alert + audit log, heartbeat sensor, 2FA Admin, backup, test end-to-end, đo precision/recall | Phần C (các mục ❌) |
| **6. Tính năng mở rộng** | Chọn từ Phần B; ưu tiên cho đồ án: MITRE ATT&CK + threat intel (B3), incident/case (B4), honeypot và LLM tóm tắt sự cố (B12) | B1–B12 |
