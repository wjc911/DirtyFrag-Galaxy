# DirtyFrag Galaxy v2.1

에페메랄 루팅 & 모듈 오케스트레이터 v2.1 릴리스.
테스트 기기: Galaxy Z Fold8 Ultra (SM-F976N, Android 17, KernelSU Next (3.4.0) + Zygisk-Next (1.5.0) + LSPosed (2.2.1))

## 하이라이트

### 1. 외부 디스플레이(DeX / 미러링) 오류 수정

- **원인**: 기존의 ksud `soft-reboot` 방식은 SurfaceFlinger까지 함께 재시작합니다.
  외부 USB-C 모니터가 연결된 상태에서 이 방식으로 재시작하면 삼성 DP 파이프(HDCP/AUX 상태)가
  부트로더 스플래시 화면에 고착되어 DeX / 미러링이 정상 복귀하지 못했습니다.
- **해결**: 소프트 재시작 방식을 **`killall system_server`(프레임워크만 재시작)** 로 변경하고,
  삼성 DP 컨트롤러의 debugfs hpd 노드를 이용한 소프트웨어 재연결을 추가했습니다.
  - `hpd 0`(park) → `killall system_server` → `setsid`로 분리된 unpark 헬퍼가
    새 system_server + DisplayManagerService 대기 → `hpd 1`(unpark)
  - 물리적으로 USB-C를 뽑았다 다시 꽂는 것과 동일한 효과를 소프트웨어로 구현
  - debugfs 접근을 위해 `su -M`(글로벌 마운트 네임스페이스)으로 실행
  - 로그: `/data/local/tmp/dirtyfrag-dp.log` (`dp-park` → `hpd 1` → `external ready`)
- 재시작 후 외부 모니터가 자동으로 복귀하며, DeX도 정상 유지됩니다.

### 2. su · Zygisk · LSPosed 모듈 감지 속도 비약적 향상 (5.28s → 1s 이하)

- **배치 프로브 1회**: uid / SELinux / 모듈 목록 / system_server pid / Zygisk 상태 / LSPosed 주입 확인을
  `su` 20~30회 중복 spawn에서 **단일 `su` 프로브**로 통합.
- **Zygisk**: `zygiskd status`(inject_state 등) 파싱 우선, 바이너리 부재 시 ps/모듈 스캔 fallback.
- **LSPosed**: durable verbose 로그 우선(20~30ms) → 0.3s 폴링 ×2 → logcat(1.1s)은 최후 fallback.
  (기존 logcat 경로가 첫 감지의 주 병목이었음)
- 감지 패스 내 결과 캐싱, 매니저 패키지 스캔 프로세스 수명 1회 캐시, fast-fail(미루팅 시 즉시 종료).
- **실측**: 첫 감지 5.28s → **0.2 ~ 0.7s**

### 3. KernelSU Next / KernelSU Next(spoof) 추가 지원

- 표준 `com.rifsxd.ksunext`와 **spoof 빌드(랜덤 패키지명)** 를 **서명 인증서 SHA-256 자동탐지**로 지원.
- 설정에서 백엔드 선택(`자동 / KernelSU / KernelSU Next`), 자동 모드는 KernelSU Next 우선.
- 매니저 실행/재시작 컴포넌트를 실제 런처(`<pkg>.ui.MainActivity`)로 정합.

### 4. 소프트 재시작 버튼 UX 개선

- 첫 감지가 끝나기 전에는 버튼이 **"확인 중…"으로 비활성**되어, 앱을 켜자마자 눌러도
  의도치 않은 즉시 재시작이 발생하지 않습니다.
- **S7(이미 활성)** 상태에서 누르면 "이미 활성화된 상태입니다. 그래도 소프트 재시작할까요?" 확인창 후 실행,
  미활성(S6)에서는 즉시 실행됩니다.

## 지원 스택

- 백엔드: KernelSU / KernelSU Next(표준 · spoof 자동탐지)
- 모듈: **Zygisk-Next + LSPosed** 권장
- NeoZygisk / Vector 등 미지원 스택은 감지 시 **"Zygisk-Next + LSPosed 교체 권장" 안내만** 표시하며
  차단하지 않습니다.

## 참고

- 릴리스 서명은 로컬 keystore로 수행되며 저장소에는 포함되지 않습니다. (`.gitignore` 참조)
- 빌드 산출물(APK)은 GitHub Releases 첨부로 배포합니다.
