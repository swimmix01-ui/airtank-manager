# 해양경찰 공기통 관리시스템

구조대 공기통의 충전 이력, 공기 유효기간, 압력검사 일정을 관리하는 모바일 웹앱(PWA)입니다.

- **배포 폴더**: `public/` (빌드 과정 없음, 파일 그대로 배포)
- **백엔드**: Firebase Authentication(공용 계정) + Cloud Firestore (프로젝트 `airssat`)
- **보안 규칙**: `firestore.rules` → Firebase 콘솔 Firestore 규칙 탭에 붙여넣고 게시
- **초기 설정 절차**: [`docs/설정가이드.md`](docs/설정가이드.md)

## 폴더 구조
```
public/
  index.html            앱 본체 (HTML·CSS·JS 한 파일)
  sw.js                 서비스워커: 오프라인 실행, 안드로이드 알림
  manifest.webmanifest  홈 화면 설치 정보
  icon-192.png, icon-512.png
firestore.rules         Firestore 보안 규칙 (배포 대상 아님)
netlify.toml            Netlify 배포 설정
tests/test_app.py       브라우저 자동 테스트 (Firebase 목업)
docs/설정가이드.md
```

## 수정·배포 방법
1. `public/index.html`을 수정합니다. 설정값은 파일 안의 `CONFIG` 블록에 모여 있습니다.
2. 앱 구조를 바꿨다면 `public/sw.js`의 `CACHE` 버전(`acm-v5.0`)도 올려야, 설치된 폰에 새 버전이 확실히 반영됩니다.
3. 커밋하고 푸시하면 Netlify가 자동으로 배포합니다.

## 테스트
```bash
pip install playwright && playwright install chromium
python3 tests/test_app.py public /tmp/shots
```
실제 Firebase에는 접속하지 않고, 가짜 Auth/Firestore 서버로 로그인, 충전, 수정, 삭제, XSS, 한국시간 날짜, 오프라인 시나리오를 검증합니다.

## 버전
- **v5.0** (2026-11): 서버 인증 + 보안 규칙, 원자적 저장, KST 날짜, XSS 차단, 통계 차트, 알림/오프라인(PWA), 검사 불합격 사용금지, UI 개편
