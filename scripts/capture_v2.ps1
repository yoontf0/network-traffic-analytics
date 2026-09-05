# v2: dumpcap 직접 사용 + 커널 버퍼 512MB + OneDrive 밖 로컬 디스크에 저장 -> 캡처 드롭 최소화
#   .\scripts\capture_v2.ps1 -Minutes 30
#   .\scripts\capture_v2.ps1 -Minutes 10 -OutDir C:\captures
param(
    [int]$Minutes = 30,
    [string]$Interface = "Wi-Fi",
    [string]$OutDir = "$env:USERPROFILE\captures_local",
    [int]$BufferMB = 512
)

$dumpcap = "C:\Program Files\Wireshark\dumpcap.exe"
if (-not (Test-Path $dumpcap)) { Write-Error "dumpcap 없음: $dumpcap"; exit 1 }
New-Item -ItemType Directory -Force $OutDir | Out-Null

$myip = (Get-NetIPAddress -InterfaceAlias $Interface -AddressFamily IPv4 |
         Where-Object { $_.IPAddress -notlike "169.254*" } | Select-Object -First 1).IPAddress
$stamp = Get-Date -Format "yyyyMMdd_HHmm"
$out = Join-Path $OutDir "home_${Minutes}min_$stamp.pcapng"

Write-Host "인터페이스 : $Interface"
Write-Host "내 IPv4    : $myip"
Write-Host "캡처 시간  : $Minutes 분, 버퍼 $BufferMB MB"
Write-Host "저장 위치  : $out"
Write-Host "캡처 시작 시각: $(Get-Date -Format 'HH:mm:ss')"

# -p non-promiscuous, -B 커널 버퍼(MB), -s 0 전체 프레임, 통계는 stderr 로
& $dumpcap -i "$Interface" -p -f "host $myip" -B $BufferMB -s 0 -a "duration:$($Minutes * 60)" -w "$out"
Write-Host "캡처 종료: $(Get-Date -Format 'HH:mm:ss')  -> $out"
