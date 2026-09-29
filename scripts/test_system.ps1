<#
.SYNOPSIS
    Kiem thu toan bo tinh nang SecNet dang chay bang Docker (goi tu test.bat).

.DESCRIPTION
    Gui request that toi he thong dang chay (backend :8080, frontend :3000, nginx :80/:443,
    TimescaleDB, Redis, capture-engine) va bao cao PASS / FAIL / WARN / SKIP cho tung tinh nang.
    Moi du lieu tao ra khi test (rule, blocklist, kenh thong bao, user) deu duoc xoa lai.

    -Full   : chay them bo test Rust (cargo test --workspace) trong container rust:bookworm,
              dung CSDL rieng "secnet_test" nen khong dung toi du lieu dang chay.
    -SendNotifications : gui "test alert" qua moi kenh thong bao dang bat (Email, Telegram...).

    Tuong thich Windows PowerShell 5.1 va PowerShell 7 (Windows/Linux).
#>
param(
    [switch]$Full,
    [switch]$SendNotifications,
    [string]$ApiBase = "http://127.0.0.1:8080",
    [string]$WebBase = "http://127.0.0.1:3000"
)

# "Continue": in Windows PowerShell 5.1, "Stop" turns any stderr output of docker/curl into a
# terminating error when redirected with 2>$null.
$ErrorActionPreference = "Continue"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# curl.exe co san tu Windows 10 1803. Trong Windows PowerShell 5.1 "curl" la alias cua
# Invoke-WebRequest nen phai goi dung curl.exe.
$Curl = if (Get-Command curl.exe -ErrorAction SilentlyContinue) { "curl.exe" } else { "curl" }
if (-not (Get-Command $Curl -ErrorAction SilentlyContinue)) {
    Write-Host "[LOI] Khong tim thay curl.exe (can Windows 10 1803 tro len)." -ForegroundColor Red
    exit 2
}

$Script:Results = New-Object System.Collections.ArrayList
$Script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("secnet_test_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Script:TmpDir | Out-Null
$RunId = (Get-Date).ToString("yyyyMMddHHmmss")

# --------------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------------

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host ("== " + $Title + " " + ("=" * [Math]::Max(0, 70 - $Title.Length))) -ForegroundColor Cyan
}

function Add-Result([string]$Status, [string]$Name, [string]$Detail = "") {
    $color = @{ PASS = "Green"; FAIL = "Red"; WARN = "Yellow"; SKIP = "DarkGray" }[$Status]
    $line = "  [{0}] {1}" -f $Status, $Name
    if ($Detail) { $line += "  -> " + $Detail }
    Write-Host $line -ForegroundColor $color
    [void]$Script:Results.Add([pscustomobject]@{ Status = $Status; Name = $Name; Detail = $Detail })
}

function Test-Check([string]$Name, [bool]$Condition, [string]$Detail = "") {
    if ($Condition) { Add-Result "PASS" $Name } else { Add-Result "FAIL" $Name $Detail }
    return $Condition
}

# Goi HTTP bang curl, tra ve @{ Status; Body; Json; ContentType }.
function Invoke-Api {
    param(
        [string]$Method = "GET",
        [string]$Url,
        [string]$Token,
        $Body,
        [switch]$Insecure,
        [int]$TimeoutSec = 20
    )
    $outFile = Join-Path $Script:TmpDir ([guid]::NewGuid().ToString("N") + ".out")
    $cargs = @("-s", "-S", "-o", $outFile, "-w", "%{http_code}|%{content_type}", "-X", $Method,
        "--max-time", "$TimeoutSec")
    if ($Insecure) { $cargs += "-k" }
    if ($Token) { $cargs += @("-H", "Authorization: Bearer $Token") }
    if ($null -ne $Body) {
        # Ghi body ra file de tranh loi quoting cua PowerShell 5.1 khi truyen JSON cho curl.exe
        $bodyFile = Join-Path $Script:TmpDir ([guid]::NewGuid().ToString("N") + ".json")
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 -Compress }
        [System.IO.File]::WriteAllText($bodyFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        $cargs += @("-H", "Content-Type: application/json", "--data-binary", "@$bodyFile")
    }
    $cargs += $Url

    $meta = & $Curl @cargs 2>$null
    $status = 0
    $ctype = ""
    if ($meta) {
        $parts = ($meta | Select-Object -Last 1).Split("|", 2)
        [int]::TryParse($parts[0], [ref]$status) | Out-Null
        if ($parts.Length -gt 1) { $ctype = $parts[1] }
    }
    $text = ""
    if (Test-Path $outFile) { $text = [System.IO.File]::ReadAllText($outFile, [System.Text.Encoding]::UTF8) }
    $parsed = $null
    if ($text -and $ctype -like "*json*") {
        try { $parsed = $text | ConvertFrom-Json } catch {}
    }
    return [pscustomobject]@{ Status = $status; Body = $text; Json = $parsed; ContentType = $ctype }
}

function Get-Short([string]$Text, [int]$Max = 160) {
    if (-not $Text) { return "" }
    $t = $Text -replace "\s+", " "
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + "..." }
    return $t
}

function Describe([object]$Resp) {
    return ("HTTP {0} {1}" -f $Resp.Status, (Get-Short $Resp.Body))
}

# Dang nhap. Tu cho 60s va thu lai mot lan neu bi rate limit (10 request/phut cho login/register).
function Invoke-Login([string]$User, [string]$Password) {
    $r = Invoke-Api -Method POST -Url "$ApiBase/api/auth/login" -Body @{ username = $User; password = $Password }
    if ($r.Status -eq 429) {
        Write-Host "  ... bi gioi han toc do dang nhap, cho 60 giay roi thu lai" -ForegroundColor DarkYellow
        Start-Sleep -Seconds 61
        $r = Invoke-Api -Method POST -Url "$ApiBase/api/auth/login" -Body @{ username = $User; password = $Password }
    }
    return $r
}

function Get-DockerState([string]$Container) {
    $out = & docker inspect --format "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}" $Container 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    $p = ($out | Select-Object -First 1).Split("|")
    return [pscustomobject]@{ Status = $p[0]; Health = $p[1] }
}

# Mo WebSocket, tra ve so message nhan duoc trong $Seconds giay (-1 neu khong ket noi duoc).
function Test-WebSocket([string]$Url, [int]$Seconds) {
    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $count = 0
    try {
        $cts = New-Object System.Threading.CancellationTokenSource
        $cts.CancelAfter([TimeSpan]::FromSeconds(10))
        [void]$ws.ConnectAsync([Uri]$Url, $cts.Token).GetAwaiter().GetResult()
        $buffer = New-Object byte[] 65536
        $seg = New-Object System.ArraySegment[byte] -ArgumentList @(, $buffer)
        $deadline = (Get-Date).AddSeconds($Seconds)
        while ((Get-Date) -lt $deadline -and $ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            $remaining = [int][Math]::Max(1, ($deadline - (Get-Date)).TotalMilliseconds)
            $rcts = New-Object System.Threading.CancellationTokenSource
            $rcts.CancelAfter($remaining)
            try {
                $res = $ws.ReceiveAsync($seg, $rcts.Token).GetAwaiter().GetResult()
                if ($res.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { break }
                if ($res.EndOfMessage) { $count++ }
                if ($count -ge 1) { break }
            } catch { break }
        }
        return $count
    } catch {
        return -1
    } finally {
        try { $ws.Dispose() } catch {}
    }
}

# --------------------------------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  SECNET - KIEM THU TOAN BO TINH NANG" -ForegroundColor Cyan
Write-Host ("  API: {0}   Web: {1}   Run: {2}" -f $ApiBase, $WebBase, $RunId) -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# --------------------------------------------------------------------------------------------
Write-Section "1. Docker & container"
# --------------------------------------------------------------------------------------------
& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Add-Result "FAIL" "Docker dang chay" "Mo Docker Desktop, doi 'Engine running' roi chay lai"
    Write-Host ""
    exit 1
}
Add-Result "PASS" "Docker dang chay"

$containers = [ordered]@{
    "secnet_timescaledb"    = $true
    "secnet_redis"          = $true
    "secnet_backend"        = $true
    "secnet_frontend"       = $true
    "secnet_nginx_tls"      = $false
    "secnet_capture_engine" = $false
}
$allUp = $true
foreach ($name in $containers.Keys) {
    $st = Get-DockerState $name
    if (-not $st) {
        Add-Result "FAIL" "Container $name" "khong ton tai - chay start_docker.bat truoc"
        $allUp = $false
    } elseif ($st.Status -ne "running") {
        Add-Result "FAIL" "Container $name" "trang thai: $($st.Status)"
        $allUp = $false
    } elseif ($containers[$name] -and $st.Health -ne "healthy") {
        Add-Result "FAIL" "Container $name" "health: $($st.Health)"
        $allUp = $false
    } else {
        $h = if ($st.Health) { " ($($st.Health))" } else { "" }
        Add-Result "PASS" ("Container $name" + $h)
    }
}
if (-not $allUp) {
    Write-Host ""
    Write-Host "  He thong chua san sang. Xem log: docker compose logs -f" -ForegroundColor Red
}

# --------------------------------------------------------------------------------------------
Write-Section "2. Ha tang: API, web, proxy, TLS, tai lieu"
# --------------------------------------------------------------------------------------------
$r = Invoke-Api -Url "$ApiBase/health"
[void](Test-Check "Backend /health" ($r.Status -eq 200 -and $r.Json.status -eq "ok") (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/health"
[void](Test-Check "Backend /api/health" ($r.Status -eq 200) (Describe $r))

$r = Invoke-Api -Url "$WebBase/"
[void](Test-Check "Frontend :3000 tra ve trang HTML" ($r.Status -eq 200 -and $r.Body -match "<html") (Describe $r))

$r = Invoke-Api -Url "$WebBase/api/health"
[void](Test-Check "Frontend proxy /api -> backend" ($r.Status -eq 200 -and $r.Json.status -eq "ok") (Describe $r))

$r = Invoke-Api -Url "http://localhost/"
[void](Test-Check "Nginx :80 chuyen huong sang HTTPS" ($r.Status -eq 301 -or $r.Status -eq 308) (Describe $r))

$r = Invoke-Api -Url "https://localhost/" -Insecure
[void](Test-Check "Nginx TLS :443 phuc vu dashboard" ($r.Status -eq 200 -and $r.Body -match "<html") (Describe $r))

$r = Invoke-Api -Url "https://localhost/api/health" -Insecure
[void](Test-Check "Nginx TLS proxy /api -> backend" ($r.Status -eq 200) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/swagger-ui/"
if ($r.Status -eq 200) { Add-Result "PASS" "Swagger UI /swagger-ui/" }
elseif ($r.Status -eq 404) { Add-Result "SKIP" "Swagger UI" "tat trong production (ENABLE_SWAGGER=false)" }
else { Add-Result "FAIL" "Swagger UI" (Describe $r) }

$r = Invoke-Api -Url "$ApiBase/api-docs/openapi.json"
if ($r.Status -eq 200) { [void](Test-Check "OpenAPI spec co cac endpoint" ($r.Json.paths.PSObject.Properties.Name.Count -gt 10)) }
elseif ($r.Status -eq 404) { Add-Result "SKIP" "OpenAPI spec" "tat trong production" }
else { Add-Result "FAIL" "OpenAPI spec" (Describe $r) }

$r = Invoke-Api -Url "$ApiBase/metrics"
if ($r.Status -eq 200) { [void](Test-Check "Prometheus /metrics" ($r.Body.Length -gt 0)) }
elseif ($r.Status -eq 401) { Add-Result "SKIP" "Prometheus /metrics" "can METRICS_TOKEN (da bat bao ve)" }
else { Add-Result "FAIL" "Prometheus /metrics" (Describe $r) }

# --------------------------------------------------------------------------------------------
Write-Section "3. CSDL TimescaleDB & Redis"
# --------------------------------------------------------------------------------------------
function Invoke-Psql([string]$Sql) {
    $out = & docker exec secnet_timescaledb psql -U postgres -d network_security -At -c $Sql 2>&1
    if ($LASTEXITCODE -ne 0) { return $null }
    return (($out | Select-Object -First 1) -as [string]).Trim()
}

$v = Invoke-Psql "SELECT count(*) FROM _sqlx_migrations WHERE success"
$migFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot "..\migrations") -Filter *.sql -ErrorAction SilentlyContinue).Count
if ($null -eq $v) { Add-Result "FAIL" "Ket noi PostgreSQL" "docker exec psql that bai" }
else {
    [void](Test-Check "Da ap dung migration ($v/$migFiles)" ([int]$v -ge $migFiles -and [int]$v -gt 0) "so migration trong DB: $v, trong thu muc: $migFiles")
}

$v = Invoke-Psql "SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name = 'traffic_events'"
[void](Test-Check "traffic_events la TimescaleDB hypertable" ($v -eq "1") "ket qua: $v")

$v = Invoke-Psql "SELECT count(*) FROM users WHERE username IN ('admin','analyst','viewer','analyst_linh','viewer_demo')"
[void](Test-Check "Co du 5 tai khoan mau" ($v -eq "5") "tim thay: $v")

$v = Invoke-Psql "SELECT count(*) FROM detection_rules"
[void](Test-Check "Co luat phat hien trong CSDL" ([int]$v -ge 8) "so luat: $v")

$pong = & docker exec secnet_redis redis-cli ping 2>$null
[void](Test-Check "Redis tra loi PING" (($pong | Select-Object -Last 1) -eq "PONG") "ket qua: $pong")

# --------------------------------------------------------------------------------------------
Write-Section "4. Xac thuc (JWT, refresh, logout, dang ky)"
# --------------------------------------------------------------------------------------------
$Accounts = @(
    @{ Role = "admin"; User = "admin"; Pass = "Admin@SecNet2026!" },
    @{ Role = "analyst"; User = "analyst"; Pass = "Analyst@SecNet2026!" },
    @{ Role = "viewer"; User = "viewer"; Pass = "Viewer@SecNet2026!" }
)
$Tokens = @{}
$AdminRefresh = $null
foreach ($a in $Accounts) {
    $r = Invoke-Login $a.User $a.Pass
    $ok = $r.Status -eq 200 -and $r.Json.data.token -and $r.Json.data.user.role -eq $a.Role
    if (Test-Check ("Dang nhap {0} / {1}" -f $a.User, $a.Pass) $ok (Describe $r)) {
        $Tokens[$a.Role] = $r.Json.data.token
        if ($a.Role -eq "admin") { $AdminRefresh = $r.Json.data.refresh_token }
    }
}
$Admin = $Tokens["admin"]; $Analyst = $Tokens["analyst"]; $Viewer = $Tokens["viewer"]

$r = Invoke-Login "secnet_test_nouser_$RunId" "WrongPassword123!"
[void](Test-Check "Sai mat khau bi tu choi (401)" ($r.Status -eq 401) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/alerts"
[void](Test-Check "Goi API khong co token bi tu choi (401)" ($r.Status -eq 401) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/alerts" -Token "abc.def.ghi"
[void](Test-Check "Token gia mao bi tu choi (401)" ($r.Status -eq 401) (Describe $r))

if ($AdminRefresh) {
    $r = Invoke-Api -Url "$ApiBase/api/alerts" -Token $AdminRefresh
    [void](Test-Check "Refresh token khong dung duoc de goi API (401)" ($r.Status -eq 401) (Describe $r))

    $r = Invoke-Api -Method POST -Url "$ApiBase/api/auth/refresh" -Body @{ refresh_token = $AdminRefresh }
    $newTok = $null
    if (Test-Check "Lam moi token bang refresh token" ($r.Status -eq 200 -and $r.Json.data.token) (Describe $r)) {
        $newTok = $r.Json.data.token
        $r2 = Invoke-Api -Method POST -Url "$ApiBase/api/auth/refresh" -Body @{ refresh_token = $AdminRefresh }
        [void](Test-Check "Refresh token chi dung duoc 1 lan (chong replay)" ($r2.Status -eq 401) (Describe $r2))
    }
    if ($newTok) {
        $r = Invoke-Api -Method POST -Url "$ApiBase/api/auth/logout" -Token $newTok -Body @{ refresh_token = $r.Json.data.refresh_token }
        [void](Test-Check "Dang xuat" ($r.Status -eq 200) (Describe $r))
        $r = Invoke-Api -Url "$ApiBase/api/alerts" -Token $newTok
        [void](Test-Check "Token da dang xuat bi thu hoi (401)" ($r.Status -eq 401) (Describe $r))
    }
}

$regUser = "test_$RunId"
$r = Invoke-Api -Method POST -Url "$ApiBase/api/auth/register" -Body @{
    username = $regUser; email = "$regUser@secnet.test"; password = "Test@SecNet2026!"; role = "admin"
}
if ($r.Status -eq 429) { Add-Result "SKIP" "Dang ky tai khoan moi" "bi gioi han toc do, chay lai sau 1 phut" }
else {
    [void](Test-Check "Dang ky tai khoan moi luon la viewer (ke ca khi xin role admin)" ($r.Status -eq 200 -and $r.Json.data.user.role -eq "viewer") (Describe $r))
}
[void](Invoke-Psql "DELETE FROM users WHERE username = '$regUser'")

if (-not $Admin) {
    Add-Result "FAIL" "Khong co token admin" "bo qua cac phan con lai"
} else {

# --------------------------------------------------------------------------------------------
Write-Section "5. Du lieu & dashboard (admin)"
# --------------------------------------------------------------------------------------------
$r = Invoke-Api -Url "$ApiBase/api/dashboard/summary" -Token $Admin
$pkt1 = 0
if (Test-Check "Dashboard summary" ($r.Status -eq 200 -and $null -ne $r.Json.data.total_packets) (Describe $r)) {
    $pkt1 = [int64]$r.Json.data.total_packets
    Write-Host ("         goi tin: {0}, bytes: {1}, canh bao: {2} (critical: {3})" -f $r.Json.data.total_packets, $r.Json.data.total_bytes, $r.Json.data.total_alerts, $r.Json.data.critical_alerts) -ForegroundColor DarkGray
}

$r = Invoke-Api -Url "$ApiBase/api/traffic?limit=20" -Token $Admin
[void](Test-Check "Danh sach luu luong (traffic)" ($r.Status -eq 200 -and @($r.Json.data).Count -gt 0) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/traffic?limit=5&protocol=TCP" -Token $Admin
[void](Test-Check "Loc luu luong theo giao thuc" ($r.Status -eq 200 -and -not (@($r.Json.data) | Where-Object { $_.protocol -ne "TCP" })) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/alerts?limit=50" -Token $Admin
$alerts = @()
if (Test-Check "Danh sach canh bao (alerts)" ($r.Status -eq 200) (Describe $r)) { $alerts = @($r.Json.data) }
if ($alerts.Count -gt 0) {
    $withMitre = @($alerts | Where-Object { $_.mitre_technique }).Count
    [void](Test-Check "Canh bao co gan nhan MITRE ATT&CK" ($withMitre -gt 0) "0/$($alerts.Count) canh bao co mitre_technique")
    $a0 = $alerts[0]
    $r = Invoke-Api -Url "$ApiBase/api/alerts/$($a0.id)" -Token $Admin
    [void](Test-Check "Chi tiet 1 canh bao" ($r.Status -eq 200 -and $r.Json.data.id -eq $a0.id) (Describe $r))
    $r = Invoke-Api -Url "$ApiBase/api/alerts/$($a0.id)/traffic" -Token $Admin
    [void](Test-Check "Goi tin lien quan canh bao (Inspect)" ($r.Status -eq 200) (Describe $r))
} else {
    Add-Result "WARN" "Chua co canh bao nao" "doi capture-engine chay them 1-2 phut"
}

$r = Invoke-Api -Url "$ApiBase/api/alerts?severity=critical&limit=10" -Token $Admin
[void](Test-Check "Loc canh bao theo muc do" ($r.Status -eq 200 -and -not (@($r.Json.data) | Where-Object { $_.severity -ne "critical" })) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/devices" -Token $Admin
if (Test-Check "Danh sach thiet bi (devices)" ($r.Status -eq 200) (Describe $r)) {
    $d = @($r.Json.data) | Select-Object -First 1
    if ($d) {
        $r = Invoke-Api -Url "$ApiBase/api/devices/$($d.id)/history" -Token $Admin
        [void](Test-Check "Lich su thiet bi" ($r.Status -eq 200) (Describe $r))
    }
}

$r = Invoke-Api -Url "$ApiBase/api/sensor/status" -Token $Admin
if (Test-Check "Trang thai sensor" ($r.Status -eq 200 -and @($r.Json.data).Count -gt 0) (Describe $r)) {
    $s = @($r.Json.data)[0]
    $ok = $s.status -match "healthy"
    if ($ok) { Add-Result "PASS" ("Sensor {0} dang {1} ({2} goi)" -f $s.sensor_id, $s.status, $s.packets_captured) }
    else { Add-Result "WARN" ("Sensor {0}" -f $s.sensor_id) ("trang thai: " + $s.status) }
}

$r = Invoke-Api -Url "$ApiBase/api/rules" -Token $Admin
[void](Test-Check "Danh sach luat phat hien" ($r.Status -eq 200 -and @($r.Json.data).Count -ge 8) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/audit-logs?limit=10" -Token $Admin
[void](Test-Check "Nhat ky kiem toan (audit logs)" ($r.Status -eq 200) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/blocklist" -Token $Admin
[void](Test-Check "Danh sach IP bi chan" ($r.Status -eq 200) (Describe $r))

$r = Invoke-Api -Url "$ApiBase/api/reports/export?format=csv" -Token $Admin
[void](Test-Check "Xuat bao cao CSV" ($r.Status -eq 200 -and $r.ContentType -like "text/csv*") ("HTTP {0} {1}" -f $r.Status, $r.ContentType))

$r = Invoke-Api -Url "$ApiBase/api/reports/export?format=pdf" -Token $Admin
[void](Test-Check "Tu choi dinh dang bao cao khong ho tro (400)" ($r.Status -eq 400) (Describe $r))

# --------------------------------------------------------------------------------------------
Write-Section "6. Capture engine & phat hien thoi gian thuc"
# --------------------------------------------------------------------------------------------
Write-Host "  ... cho 6 giay de do luu luong moi" -ForegroundColor DarkGray
Start-Sleep -Seconds 6
$r = Invoke-Api -Url "$ApiBase/api/dashboard/summary" -Token $Admin
$pkt2 = if ($r.Json) { [int64]$r.Json.data.total_packets } else { 0 }
[void](Test-Check "Luu luong moi duoc ghi vao CSDL" ($pkt2 -gt $pkt1) ("truoc: $pkt1, sau: $pkt2"))

$v = Invoke-Psql "SELECT count(*) FROM alerts WHERE detected_at > now() - interval '15 minutes'"
if ([int]$v -gt 0) { Add-Result "PASS" "Phat hien tan cong trong 15 phut qua ($v canh bao)" }
else { Add-Result "WARN" "Chua co canh bao nao trong 15 phut qua" "kiem tra DEMO_SCENARIO va log capture-engine" }

$v = Invoke-Psql "SELECT string_agg(DISTINCT coalesce(mitre_technique,'?'), ', ') FROM alerts WHERE detected_at > now() - interval '1 hour'"
if ($v) { Write-Host "         Ky thuat MITRE phat hien trong 1 gio: $v" -ForegroundColor DarkGray }

$wsBase = $ApiBase -replace "^http", "ws"
$n = Test-WebSocket "$wsBase/ws/traffic?token=$Admin" 10
if ($n -gt 0) { Add-Result "PASS" "WebSocket /ws/traffic nhan du lieu realtime" }
elseif ($n -eq 0) { Add-Result "FAIL" "WebSocket /ws/traffic" "ket noi duoc nhung khong nhan message trong 10s" }
else { Add-Result "FAIL" "WebSocket /ws/traffic" "khong ket noi duoc" }

$n = Test-WebSocket "$wsBase/ws/traffic?token=invalid" 2
[void](Test-Check "WebSocket tu choi token sai" ($n -lt 0) "van ket noi duoc voi token sai")

$webWs = $WebBase -replace "^http", "ws"
$n = Test-WebSocket "$webWs/ws/traffic?token=$Admin" 10
if ($n -gt 0) { Add-Result "PASS" "WebSocket qua proxy frontend :3000" }
else { Add-Result "FAIL" "WebSocket qua proxy frontend :3000" "khong nhan duoc du lieu" }

$n = Test-WebSocket "$wsBase/ws/alerts?token=$Admin" 20
if ($n -gt 0) { Add-Result "PASS" "WebSocket /ws/alerts nhan canh bao realtime" }
elseif ($n -eq 0) { Add-Result "WARN" "WebSocket /ws/alerts" "ket noi duoc, chua co canh bao moi trong 20s (binh thuong neu dang giua 2 kich ban)" }
else { Add-Result "FAIL" "WebSocket /ws/alerts" "khong ket noi duoc" }

# --------------------------------------------------------------------------------------------
Write-Section "7. Phan quyen RBAC"
# --------------------------------------------------------------------------------------------
$sampleRule = @{
    name = "rbac_probe_$RunId"; rule_type = "threshold"; condition_json = @{ metric = "packets" }
    severity = "low"; threshold_value = 1; time_window_seconds = 60; is_enabled = $false
}
$sampleBlock = @{ ip_address = "203.0.113.251"; reason = "rbac probe"; duration_seconds = 60 }
$openAlert = $alerts | Where-Object { $_.status -eq "open" } | Select-Object -First 1

foreach ($role in @("viewer", "analyst")) {
    $tok = $Tokens[$role]
    if (-not $tok) { Add-Result "SKIP" "RBAC $role" "khong dang nhap duoc"; continue }
    $r = Invoke-Api -Url "$ApiBase/api/dashboard/summary" -Token $tok
    [void](Test-Check "$role xem duoc dashboard" ($r.Status -eq 200) (Describe $r))
    $r = Invoke-Api -Url "$ApiBase/api/audit-logs" -Token $tok
    [void](Test-Check "$role KHONG xem duoc audit log (403)" ($r.Status -eq 403) (Describe $r))
    $r = Invoke-Api -Method POST -Url "$ApiBase/api/rules" -Token $tok -Body $sampleRule
    [void](Test-Check "$role KHONG tao duoc luat (403)" ($r.Status -eq 403) (Describe $r))
    $r = Invoke-Api -Method POST -Url "$ApiBase/api/blocklist" -Token $tok -Body $sampleBlock
    [void](Test-Check "$role KHONG chan duoc IP (403)" ($r.Status -eq 403) (Describe $r))
    $r = Invoke-Api -Method POST -Url "$ApiBase/api/notifications/channels" -Token $tok -Body @{
        name = "rbac_probe"; type = "webhook"; config_json = @{ endpoint_url = "https://example.com/hook" }; min_severity = "high"; is_enabled = $false
    }
    [void](Test-Check "$role KHONG tao duoc kenh thong bao (403)" ($r.Status -eq 403) (Describe $r))
}
if ($Viewer -and $openAlert) {
    $r = Invoke-Api -Method PATCH -Url "$ApiBase/api/alerts/$($openAlert.id)" -Token $Viewer -Body @{ status = "acknowledged" }
    [void](Test-Check "viewer KHONG xu ly duoc su co (403)" ($r.Status -eq 403) (Describe $r))
}

# --------------------------------------------------------------------------------------------
Write-Section "8. Vong doi su co (Acknowledge -> Resolve -> Reopen)"
# --------------------------------------------------------------------------------------------
if ($Analyst -and $openAlert) {
    $id = $openAlert.id
    $r = Invoke-Api -Method PATCH -Url "$ApiBase/api/alerts/$id" -Token $Analyst -Body @{ status = "acknowledged" }
    [void](Test-Check "analyst xac nhan (acknowledge) su co" ($r.Status -eq 200 -and $r.Json.data.status -eq "acknowledged") (Describe $r))
    $r = Invoke-Api -Method PATCH -Url "$ApiBase/api/alerts/$id" -Token $Analyst -Body @{ status = "resolved" }
    [void](Test-Check "analyst dong (resolve) su co" ($r.Status -eq 200 -and $r.Json.data.status -eq "resolved" -and $r.Json.data.resolved_at) (Describe $r))
    $r = Invoke-Api -Method PATCH -Url "$ApiBase/api/alerts/$id" -Token $Admin -Body @{ status = "open" }
    [void](Test-Check "admin mo lai (reopen) su co" ($r.Status -eq 200 -and $r.Json.data.status -eq "open") (Describe $r))
} else {
    Add-Result "SKIP" "Vong doi su co" "khong co canh bao dang mo de thu"
}

# --------------------------------------------------------------------------------------------
Write-Section "9. Quan ly luat phat hien (CRUD + audit)"
# --------------------------------------------------------------------------------------------
$ruleName = "secnet_test_rule_$RunId"
$r = Invoke-Api -Method POST -Url "$ApiBase/api/rules" -Token $Admin -Body @{
    name = $ruleName; rule_type = "threshold"; condition_json = @{ metric = "packets"; note = "created by test.bat" }
    severity = "low"; threshold_value = 999999; time_window_seconds = 60; is_enabled = $false
    mitre_tactic = "Discovery"; mitre_technique = "T1046"
}
if (Test-Check "Tao luat moi" ($r.Status -eq 200 -and $r.Json.data.id) (Describe $r)) {
    $rid = $r.Json.data.id
    $r = Invoke-Api -Url "$ApiBase/api/rules/$rid" -Token $Admin
    [void](Test-Check "Doc luat vua tao" ($r.Status -eq 200 -and $r.Json.data.name -eq $ruleName) (Describe $r))
    $r = Invoke-Api -Method PATCH -Url "$ApiBase/api/rules/$rid" -Token $Admin -Body @{ threshold_value = 12345; severity = "medium" }
    [void](Test-Check "Sua luat (nguong, muc do)" ($r.Status -eq 200 -and [double]$r.Json.data.threshold_value -eq 12345 -and $r.Json.data.severity -eq "medium") (Describe $r))
    $r = Invoke-Api -Method POST -Url "$ApiBase/api/rules" -Token $Admin -Body @{
        name = $ruleName; rule_type = "threshold"; condition_json = @{}; severity = "low"; threshold_value = 1; time_window_seconds = 60
    }
    [void](Test-Check "Tu choi luat trung ten (400)" ($r.Status -eq 400) (Describe $r))
    $r = Invoke-Api -Method POST -Url "$ApiBase/api/rules" -Token $Admin -Body @{
        name = "x"; rule_type = "threshold"; condition_json = @{}; severity = "low"; threshold_value = -1; time_window_seconds = 0
    }
    [void](Test-Check "Tu choi luat khong hop le (400/422)" ($r.Status -eq 400 -or $r.Status -eq 422) (Describe $r))
    $r = Invoke-Api -Method DELETE -Url "$ApiBase/api/rules/$rid" -Token $Admin
    [void](Test-Check "Xoa luat" ($r.Status -eq 200 -or $r.Status -eq 204) (Describe $r))
    $r = Invoke-Api -Url "$ApiBase/api/rules/$rid" -Token $Admin
    [void](Test-Check "Luat da xoa khong con (404)" ($r.Status -eq 404) (Describe $r))
    $v = Invoke-Psql "SELECT count(*) FROM audit_logs WHERE target = '$ruleName' AND action IN ('CREATE_RULE','UPDATE_RULE','DELETE_RULE')"
    [void](Test-Check "Audit log ghi lai tao/sua/xoa luat" ([int]$v -ge 3) "so ban ghi: $v")
}

# --------------------------------------------------------------------------------------------
Write-Section "10. Chan IP (blocklist / IPS)"
# --------------------------------------------------------------------------------------------
$testIp = "203.0.113.250"
$r = Invoke-Api -Method POST -Url "$ApiBase/api/blocklist" -Token $Admin -Body @{ ip_address = $testIp; reason = "secnet test.bat $RunId"; duration_seconds = 300 }
if (Test-Check "Chan IP $testIp trong 5 phut" ($r.Status -eq 200 -and $r.Json.data.id) (Describe $r)) {
    $bid = $r.Json.data.id
    $r = Invoke-Api -Url "$ApiBase/api/blocklist" -Token $Admin
    [void](Test-Check "IP xuat hien trong blocklist" (@($r.Json.data | Where-Object { $_.id -eq $bid }).Count -eq 1) (Describe $r))
    $r = Invoke-Api -Method DELETE -Url "$ApiBase/api/blocklist/$bid" -Token $Admin
    [void](Test-Check "Bo chan IP" ($r.Status -eq 200 -or $r.Status -eq 204) (Describe $r))
}
$r = Invoke-Api -Method POST -Url "$ApiBase/api/blocklist" -Token $Admin -Body @{ ip_address = "not-an-ip"; reason = "invalid test" }
[void](Test-Check "Tu choi IP sai dinh dang (400)" ($r.Status -eq 400) (Describe $r))
$r = Invoke-Api -Method POST -Url "$ApiBase/api/blocklist" -Token $Admin -Body @{ ip_address = "127.0.0.1"; reason = "loopback test" }
[void](Test-Check "Khong cho chan dia chi loopback (400)" ($r.Status -eq 400) (Describe $r))

# --------------------------------------------------------------------------------------------
Write-Section "11. Kenh thong bao (Email / Telegram / Slack / Webhook)"
# --------------------------------------------------------------------------------------------
$r = Invoke-Api -Method POST -Url "$ApiBase/api/notifications/channels" -Token $Admin -Body @{
    name = "secnet_test_ssrf_$RunId"; type = "webhook"; config_json = @{ endpoint_url = "http://127.0.0.1:8080/health" }; min_severity = "high"; is_enabled = $false
}
[void](Test-Check "Chong SSRF: tu choi webhook tro vao IP noi bo (400)" ($r.Status -eq 400) (Describe $r))
if ($r.Json -and $r.Json.data.id) { [void](Invoke-Api -Method DELETE -Url "$ApiBase/api/notifications/channels/$($r.Json.data.id)" -Token $Admin) }

$secretToken = "123456789:SECNETTESTSECRET$RunId"
$r = Invoke-Api -Method POST -Url "$ApiBase/api/notifications/channels" -Token $Admin -Body @{
    name = "secnet_test_tg_$RunId"; type = "telegram"; config_json = @{ bot_token = $secretToken; chat_id = "-100123" }; min_severity = "critical"; is_enabled = $false
}
if (Test-Check "Tao kenh Telegram (tat san)" ($r.Status -eq 200 -and $r.Json.data.id) (Describe $r)) {
    $cid = $r.Json.data.id
    $r = Invoke-Api -Method PATCH -Url "$ApiBase/api/notifications/channels/$cid" -Token $Admin -Body @{ min_severity = "high" }
    [void](Test-Check "Sua kenh thong bao" ($r.Status -eq 200 -and $r.Json.data.min_severity -eq "high") (Describe $r))
    if ($Viewer) {
        $r = Invoke-Api -Url "$ApiBase/api/notifications/channels" -Token $Viewer
        $ch = @($r.Json.data | Where-Object { $_.id -eq $cid }) | Select-Object -First 1
        [void](Test-Check "An bi mat (bot_token) voi nguoi khong phai admin" ($r.Status -eq 200 -and $ch -and $ch.config_json.bot_token -ne $secretToken) (Describe $r))
    }
    $r = Invoke-Api -Method DELETE -Url "$ApiBase/api/notifications/channels/$cid" -Token $Admin
    [void](Test-Check "Xoa kenh thong bao" ($r.Status -eq 200 -or $r.Status -eq 204) (Describe $r))
}

$r = Invoke-Api -Url "$ApiBase/api/notifications/channels" -Token $Admin
$enabled = @($r.Json.data | Where-Object { $_.is_enabled })
foreach ($ch in @($r.Json.data)) {
    $cfg = $ch.config_json
    if ($ch.type -eq "email" -and $ch.is_enabled) {
        $hasCred = [bool]($cfg.smtp_username -or $cfg.username)
        [void](Test-Check ("Kenh email '{0}' co tai khoan SMTP" -f $ch.name) $hasCred ("thieu Username/Password - server {0} se tra loi 530" -f $cfg.smtp_host))
    }
}
if ($enabled.Count -eq 0) {
    Add-Result "SKIP" "Gui thu qua kenh thong bao" "chua co kenh nao dang bat"
} elseif (-not $SendNotifications) {
    Add-Result "SKIP" ("Gui thu qua {0} kenh dang bat" -f $enabled.Count) "chay 'test.bat notify' de gui that"
} else {
    foreach ($ch in $enabled) {
        $r = Invoke-Api -Method POST -Url "$ApiBase/api/notifications/test/$($ch.id)" -Token $Admin -TimeoutSec 40
        $ok = $r.Status -eq 200
        $detail = if ($r.Json -and $r.Json.message) { $r.Json.message } elseif ($r.Json -and $r.Json.error) { $r.Json.error } else { Get-Short $r.Body 220 }
        [void](Test-Check ("Gui test alert qua {0} '{1}'" -f $ch.type, $ch.name) $ok $detail)
    }
}

} # end if $Admin

# --------------------------------------------------------------------------------------------
if ($Full) {
    Write-Section "12. Bo test Rust (cargo test --workspace) trong Docker"
    Write-Host "  Lan dau mat 10-20 phut de tai image rust va bien dich. Cac lan sau dung cache." -ForegroundColor DarkGray
    $root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $network = (& docker inspect secnet_timescaledb --format "{{range `$k, `$v := .NetworkSettings.Networks}}{{`$k}}{{end}}" 2>$null | Select-Object -First 1)
    if (-not $network) {
        Add-Result "FAIL" "Bo test Rust" "khong tim thay mang Docker cua secnet_timescaledb"
    } else {
        & docker exec secnet_timescaledb psql -U postgres -d postgres -q -c "DROP DATABASE IF EXISTS secnet_test WITH (FORCE)" *> $null
        & docker exec secnet_timescaledb psql -U postgres -d postgres -q -c "CREATE DATABASE secnet_test" *> $null
        $cmd = "apt-get update -qq >/dev/null && apt-get install -y -qq libpcap-dev pkg-config libssl-dev >/dev/null && cargo test --workspace --color always 2>&1 | tee /tmp/cargo_test.log; exit `${PIPESTATUS[0]}"
        & docker run --rm --network $network `
            -e "DATABASE_URL=postgres://postgres:postgres@timescaledb:5432/secnet_test" `
            -e "SQLX_OFFLINE=true" `
            -e "CARGO_TARGET_DIR=/cargo-target" `
            -v "${root}:/src" -w /src `
            -v "secnet_test_cargo_registry:/usr/local/cargo/registry" `
            -v "secnet_test_cargo_target:/cargo-target" `
            rust:bookworm bash -c $cmd
        $code = $LASTEXITCODE
        & docker exec secnet_timescaledb psql -U postgres -d postgres -q -c "DROP DATABASE IF EXISTS secnet_test WITH (FORCE)" *> $null
        [void](Test-Check "cargo test --workspace (unit + integration + benchmark)" ($code -eq 0) "exit code $code - xem log phia tren")
    }
} else {
    Write-Section "12. Bo test Rust"
    Add-Result "SKIP" "cargo test --workspace" "chay 'test.bat full' de chay them"
}

# --------------------------------------------------------------------------------------------
Remove-Item -Recurse -Force $Script:TmpDir -ErrorAction SilentlyContinue

$pass = @($Script:Results | Where-Object Status -eq "PASS").Count
$fail = @($Script:Results | Where-Object Status -eq "FAIL").Count
$warn = @($Script:Results | Where-Object Status -eq "WARN").Count
$skip = @($Script:Results | Where-Object Status -eq "SKIP").Count

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ("  KET QUA:  PASS {0}   FAIL {1}   WARN {2}   SKIP {3}" -f $pass, $fail, $warn, $skip) -ForegroundColor $(if ($fail -gt 0) { "Red" } else { "Green" })
Write-Host "=====================================================================" -ForegroundColor Cyan
if ($fail -gt 0) {
    Write-Host "  Cac muc that bai:" -ForegroundColor Red
    $Script:Results | Where-Object Status -eq "FAIL" | ForEach-Object {
        Write-Host ("   - {0}: {1}" -f $_.Name, $_.Detail) -ForegroundColor Red
    }
}

$report = Join-Path (Join-Path $PSScriptRoot "..") "test_report.txt"
$lines = @("SecNet test report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", "PASS $pass  FAIL $fail  WARN $warn  SKIP $skip", "")
$lines += $Script:Results | ForEach-Object { "[{0}] {1}{2}" -f $_.Status, $_.Name, $(if ($_.Detail) { "  -> " + $_.Detail } else { "" }) }
[System.IO.File]::WriteAllLines($report, $lines, (New-Object System.Text.UTF8Encoding($true)))
Write-Host "  Bao cao da luu: test_report.txt"
Write-Host ""

if ($fail -gt 0) { exit 1 } else { exit 0 }
