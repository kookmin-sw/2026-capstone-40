"""
ShapeContentV1Method: CSS 클래스 수집 이전 버전 (텍스트 토큰만 비교)

수정 전 알고리즘:
    매칭된 서브트리에서 텍스트 토큰만 수집 → 통합 Jaccard
    (CSS 클래스 미포함)
"""

from __future__ import annotations

from utils.html_similarity.methods.base import HTMLSimilarityMethod
from utils.html_similarity.methods.shape_content import _build_info, _greedy_match, _tokenize, _jaccard
from utils.html_similarity.preprocessor import parse


class ShapeContentV1Method(HTMLSimilarityMethod):

    def compute(self, html_a: str, html_b: str) -> float:
        soup_a = parse(html_a)
        soup_b = parse(html_b)

        info_a = _build_info(soup_a)
        info_b = _build_info(soup_b)

        if not info_a or not info_b:
            return 0.0

        matches = _greedy_match(info_a, info_b)
        if not matches:
            return 0.0

        pool_a: set[str] = set()
        pool_b: set[str] = set()
        for m in matches:
            pool_a.update(_tokenize(m["text_a"]))
            pool_b.update(_tokenize(m["text_b"]))
            # CSS 클래스 미포함 (수정 이전)

        if not pool_a and not pool_b:
            return 0.0
        return round(_jaccard(pool_a, pool_b), 4)

    @property
    def name(self) -> str:
        return "shape_content_v1"

    @property
    def description(self) -> str:
        return "태그 무관 형태 매칭 서브트리 내 텍스트만 Jaccard (CSS 미포함)"
