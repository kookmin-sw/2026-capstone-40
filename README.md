# Capstone 2026 Pages 브랜치

이 브랜치는 Capstone 2026 Team 40의 GitHub Pages 사이트를 담고 있습니다.

애플리케이션 소스 코드는 이 브랜치에 의도적으로 보관하지 않습니다. 사이트는 `src/main.rs`의 작은 Rust 정적 사이트 생성기가 `book/`의 Markdown 콘텐츠를 사용해 생성하며, `.github/workflows/pages.yml`의 GitHub Actions 워크플로로 배포합니다.

## 로컬 미리보기

정적 사이트를 빌드합니다:

```bash
cargo run --release
```

생성된 사이트는 다음 위치에 작성됩니다:

```text
site/
```

이미지나 영상 썸네일 같은 정적 자산은 `assets/`에 둡니다. 빌드 시 해당 파일들은 `site/assets/`로 복사됩니다.

GitHub Pages 배포를 위해서는 `page` 브랜치에 push하고, 저장소의 Pages 소스가 GitHub Actions를 사용하도록 설정되어 있는지 확인합니다.
