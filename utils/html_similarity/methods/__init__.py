"""
HTML 유사도 측정 방법 레지스트리

새 방법 추가:
    1. methods/ 아래 파일 작성 (HTMLSimilarityMethod 상속)
    2. METHOD_REGISTRY 에 등록

사용 예:
    methods = get_all_methods()          # 등록된 모든 방법
    method  = get_method("dom_sequence") # 특정 방법만
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from utils.html_similarity.methods.shape_content import ShapeContentMethod

if TYPE_CHECKING:
    from utils.html_similarity.methods.base import HTMLSimilarityMethod

METHOD_REGISTRY: dict[str, type] = {
    "shape_content": ShapeContentMethod,
}


def get_method(name: str) -> "HTMLSimilarityMethod":
    if name not in METHOD_REGISTRY:
        raise ValueError(f"Unknown method '{name}'. Available: {list(METHOD_REGISTRY.keys())}")
    return METHOD_REGISTRY[name]()


def get_all_methods() -> list["HTMLSimilarityMethod"]:
    return [cls() for cls in METHOD_REGISTRY.values()]


def list_methods() -> list[str]:
    return list(METHOD_REGISTRY.keys())
