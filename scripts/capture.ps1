# 홈 Wi-Fi 에서 내 호스트 트래픽만 30분 캡처 (관리자 PowerShell 에서 실행 권장)
#   .\scripts\capture.ps1                     -> 30분
#   .\scripts\capture.ps1 -Minutes 1          -> 1분 (파이프라인 테스트용)
#   .\scripts\capture.ps1 -Interface "Wi-Fi"  -> 인터페이스 이름 직접 지정
param(
    [int]$Minutes = 30,
    [string]$Interface = "",
    [string]$Out = ""
)

$tshark = "C:\Program Files\Wireshark\tshark.exe"
if (-not (Test-Path $tshark)) { Write-Error "tshark 없음: $tshark"; exit 1 }

$root = Split-Path -Parent $PSScriptRoot
if ($Out -eq "") {
    $stamp = Get-Date -Format "yyyyMMdd_HHmm"
    $Out = Join-Path $root "captures\home_${Minutes}min_$stamp.pcapng"
}
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null

# 활성 Wi-Fi 인터페이스 + 내 IPv4 자동 탐지
if ($Interface -eq "") {
    $ad = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.PhysicalMediaType -match "802.11|Native 802.11" } | Select-Object -First 1
    if (-not $ad) { $ad = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and -not $_.Virtual } | Select-Object -First 1 }
    $Interface = $ad.Name
}
$myip = (Get-NetIPAddress -InterfaceAlias $Interface -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.254*" } | Select-Object -First 1).IPAddress

Write-Host "인터페이스 : $Interface"
Write-Host "내 IPv4    : $myip"
Write-Host "캡처 시간  : $Minutes 분"
Write-Host "저장 위치  : $Out"
Write-Host "캡처 시작 시각: $(Get-Date -Format 'HH:mm:ss')  (활동 로그에 이 시각을 기준으로 적으세요)"

# -p : non-promiscuous (내 NIC 로 오가는 프레임만)
# -f : 캡처 필터로 내 IP 관련 패킷만 (브로드캐스트/다른 기기 제외)
$dur = $Minutes * 60
& $tshark -i "$Interface" -p -f "host $myip" -a "duration:$dur" -w "$Out"
Write-Host "캡처 종료: $(Get-Date -Format 'HH:mm:ss')  -> $Out"
