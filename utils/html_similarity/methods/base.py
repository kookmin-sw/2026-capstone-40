"""
HTMLSimilarityMethod: HTML 유사도 측정 추상 기반 클래스

새 방법 추가:
    1. 이 클래스 상속
    2. compute() 구현
    3. methods/__init__.py 의 METHOD_REGISTRY 에 등록
"""

from abc import ABC, abstractmethod


class HTMLSimilarityMethod(ABC):

    @abstractmethod
    def compute(self, html_a: str, html_b: str) -> float:
        """두 HTML 문자열의 유사도를 0~1 범위로 반환.

        Args:
            html_a, html_b: 원본 HTML 문자열

        Returns:
            float: 0.0 (완전 다름) ~ 1.0 (완전 동일)
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """방법 식별자 (엑셀 시트명, 로그 등에 사용)."""

    @property
    @abstractmethod
    def description(self) -> str:
        """방법 설명 (엑셀 헤더 등에 표시)."""
