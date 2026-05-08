"""
HTML 전처리기

파싱 전에 공통으로 적용:
- 노이즈 태그 제거: script, style, head, link, meta, noscript, comment
- 인코딩 정규화

dom_sequence 방식은 여기서 정제된 soup 을 받아 사용.
html_similarity 패키지는 자체 파서를 쓰므로 raw string 을 그대로 전달.
"""

from __future__ import annotations

from bs4 import BeautifulSoup, Comment

# 파싱 결과에서 제거할 태그 (스크립트/스타일/메타 등 구조 무관 노이즈)
_NOISE_TAGS = {"script", "style", "head", "link", "meta", "noscript", "iframe",
               "svg", "canvas", "template"}


def parse(html: str) -> BeautifulSoup:
    """HTML 문자열 → 정제된 BeautifulSoup 객체.

    노이즈 태그와 주석을 제거한다.
    구조 분석에 관련 없는 태그는 여기서 일괄 제거.
    """
    soup = BeautifulSoup(html, "html.parser")

    # 노이즈 태그 제거
    for tag in soup(list(_NOISE_TAGS)):
        tag.decompose()

    # HTML 주석 제거
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()

    return soup


def load(path: str) -> str:
    """HTML 파일 로드 (UTF-8, 오류는 무시)."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        return f.read()
