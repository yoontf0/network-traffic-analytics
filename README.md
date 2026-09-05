# network-traffic-analytics

**홈 네트워크 트래픽 품질 지표(RTT · TCP 재전송률 · DNS 응답시간 · 처리량)를 tshark + Python 으로 집계하고,
SPC I-Chart(중심선 ± 3σ)로 품질 이상 구간을 자동 검출하는 파이프라인**

> 데이터네트워크 수업의 Wireshark 실습(HTTP / DNS / TCP 패킷 분석)을 개인 프로젝트로 확장한 것이다.
> 수업에서는 패킷 하나하나를 GUI 로 읽었다면, 여기서는 **30분치 트래픽을 통째로 시계열 지표로 바꾸고
> "정상 범위"를 통계적으로 정의해 이상 구간을 자동으로 찾는 것**이 목표다.
> 관리도(I-Chart) 기법은 반도체 식각 공정 실습에서 사용했던 것
> ([etch-doe-optimizer/src/spc.py](https://github.com/yoontf0/etch-doe-optimizer/blob/main/src/spc.py))을
> 네트워크 운용 데이터에 그대로 재적용했다.

> ⚠️ 이 저장소에는 **raw pcap 과 패킷 단위 CSV 를 포함하지 않는다** (개인 트래픽 - IP, 방문 사이트 정보 포함).
> `results/` 에는 1분 단위 집계값과 그래프만 있으며, 모든 IP 는 `192.168.x.x` 형식으로 마스킹되어 있다.

---

## 1. 배경: 수업 실습 → 개인 확장

| | 수업 실습 (Kurose & Ross Wireshark Lab) | 이 프로젝트 |
|---|---|---|
| 대상 | 단일 HTTP 요청, DNS 질의 1회, TCP 연결 1개 | 30분 동안의 전체 홈 트래픽 ({{PACKETS}} 패킷) |
| 도구 | Wireshark GUI 로 필드 읽기 | tshark CLI 필드 추출 → pandas 집계 → matplotlib |
| 질문 | "SYN 의 seq 번호는?", "DNS 응답 포트는?" | "품질이 평소보다 나빠진 구간은 언제이고 왜인가?" |
| 판단 기준 | 없음 (관찰) | I-Chart 관리한계 (CL ± 3σ) 로 정량 판정 |

## 2. 방법론

### 2.1 캡처
- 환경: 노트북 1대, 홈 Wi-Fi, 유선/VPN 없음
- `tshark -i Wi-Fi -p -f "host <내 IP>" -a duration:1800 -w capture.pcapng` ([scripts/capture.ps1](scripts/capture.ps1))
  - `-p` (non-promiscuous) + `host` 캡처 필터로 **내 기기 트래픽만** 수집
- 트래픽 패턴이 다양하게 나오도록 3가지 활동을 10분씩 진행 ([docs/capture_plan.md](docs/capture_plan.md))

| 경과 시간 | 활동 |
|---|---|
| 0 ~ 10분 | 웹 서핑 (여러 사이트 방문) |
| 10 ~ 20분 | 유튜브 스트리밍 |
| 20 ~ 30분 | 대용량 파일 다운로드 |

### 2.2 필드 추출 (tshark)
```
tshark -r capture.pcapng -n -T fields -E header=y -E separator=, \
  -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len \
  -e tcp.stream -e tcp.analysis.ack_rtt -e tcp.analysis.retransmission \
  -e tcp.analysis.fast_retransmission -e tcp.analysis.spurious_retransmission \
  -e dns.time -e dns.flags.response ...
```

### 2.3 1분 구간(bin) 집계 ([src/aggregate.py](src/aggregate.py))

| 지표 | 정의 | 주의한 점 |
|---|---|---|
| **RTT** [ms] | `tcp.analysis.ack_rtt` 의 1분 평균 / 최대 / p95 | **서버 → 내 호스트 방향 ACK 만 사용.** 내 호스트가 보낸 ACK 의 ack_rtt 는 delayed-ACK 지연(최대 200 ms)이 섞여 네트워크 RTT 가 아니다. 표본 5개 미만 구간은 결측 처리 |
| **재전송률** [%] | (retransmission + fast retransmission) / 전체 TCP 세그먼트 × 100 | spurious retransmission 은 실제 손실이 아니므로 분리 집계 |
| **DNS 응답시간** [ms] | `dns.time` (query → response) 평균 / 최대 | 응답 패킷 기준 |
| **처리량** [Mbps] | Σ frame.len × 8 / 60 s | 다운/업 방향 분리 |

### 2.4 I-Chart (개별값 관리도) ([src/spc.py](src/spc.py))
- 각 1분 구간값을 하나의 개별 관측치로 보고, 이동범위(Moving Range)로 σ 를 추정
  - σ̂ = MR̄ / d₂ (n=2 → d₂ = 1.128), **UCL = CL + 3σ̂ = CL + 2.66·MR̄**, LCL 은 0 에서 절단
- 반도체 SPC 와 동일한 공식. 차이는 "로트별 식각률" 대신 "1분별 RTT / 재전송률" 이 들어간다는 것뿐
- UCL 초과 구간 = "관리 이탈(out-of-control)" → 해당 시간대의 처리량·프로토콜·활동 로그와 대조해 원인 추정

## 3. 결과

{{RESULTS}}

## 4. 한계와 다음 단계
- **표본 1회(30분)**: 관리한계가 이 캡처 자체에서 추정된 값이라 "평소 대비" 가 아니라 "이 30분의 평균 대비" 이다. 운용 관제라면 정상 기간의 기준선(baseline)을 먼저 확보하고 그 한계를 새 데이터에 적용해야 한다.
- **3σ 단일 규칙**: 서서히 나빠지는 추세(drift)는 잡지 못한다 → Western Electric rules(연속 8점 편측, 2/3점 2σ 초과 등) 또는 EWMA/CUSUM 관리도 추가가 다음 단계.
- **활동 의존성**: RTT·재전송률의 분산은 사용자가 무엇을 했는지(스트리밍 vs 다운로드)에 크게 좌우된다. 동일 조건 반복 측정 또는 활동별 층화(stratified) 관리도가 필요하다.
- **단일 관측점**: 클라이언트 한 곳에서 본 값이라 손실이 Wi-Fi 구간인지 ISP/서버 구간인지 구분 못 한다. 게이트웨이·서버 측 지표와 교차하면 구간 분리가 가능하다.

## 5. 실행 방법
```bash
pip install -r requirements.txt
# 1) 캡처 (관리자 PowerShell, Wireshark/Npcap 설치 필요)
.\scripts\capture.ps1 -Minutes 30
# 2) 분석
python run_pipeline.py --pcap captures\home_30min_<날짜>.pcapng
# 3) 테스트
python -m pytest -q tests
```

```
network-traffic-analytics/
├─ run_pipeline.py        # pcap → 추출 → 집계 → I-chart → 그래프/요약
├─ src/
│  ├─ extract.py          # tshark 필드 추출, CSV 로드, 호스트 IP 추정
│  ├─ aggregate.py        # 1분 구간 지표 집계, 프로토콜 구성
│  ├─ spc.py              # I-Chart 관리한계, 이탈 구간 검출
│  ├─ visualize.py        # 그래프 3장
│  └─ mask.py             # IP 마스킹
├─ scripts/capture.ps1    # tshark 캡처 (내 호스트만, 30분)
├─ tests/                 # SPC / 집계 단위 테스트 (pytest)
├─ docs/                  # 캡처 시나리오, 활동 로그
└─ results/               # 집계 CSV + 그래프 + summary.json (IP 마스킹)
   (captures/, data/ 는 .gitignore - raw 데이터 비공개)
```
