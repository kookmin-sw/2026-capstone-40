"""
Excel 출력

results.xlsx 시트 구성:
    dom_sequence   : DOM 시퀀스 유사도 행렬 (이름 순 정렬, 셀 색상)
    html_similarity: html-similarity 패키지 유사도 행렬
    비교_목록       : 모든 쌍 × 모든 방법 점수 나란히 (유사도 내림차순)
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

_THIN     = Side(style="thin", color="CCCCCC")
_BORDER   = Border(left=_THIN, right=_THIN, top=_THIN, bottom=_THIN)
_HDR_FILL = PatternFill("solid", fgColor="2F4F7F")
_HDR_FONT = Font(bold=True, color="FFFFFF", size=10)
_CENTER   = Alignment(horizontal="center", vertical="center", wrap_text=True)


def _extract_domain(filename: str) -> str:
    """linkkf.live_260430.html → linkkf.live"""
    m = re.match(r"^(.+?)_\d{6}", filename)
    return m.group(1) if m else filename


def save(
    results: list[dict],
    method_names: list[str],
    output_path: Path,
    site_groups: dict[str, list[str]] | None = None,
    top_n: int = 20,
) -> None:
    """분석 결과를 results.xlsx 에 저장.

    Args:
        results     : [{"file_a": str, "file_b": str, method_name: float, ...}, ...]
        method_names: 점수 컬럼명 목록
        output_path : 저장 경로
    """
    labels = sorted({r["file_a"] for r in results} | {r["file_b"] for r in results})

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        # 요약 시트 (첫 번째)
        _write_summary(writer, results, method_names, site_groups or {}, top_n)

        # 방법별 행렬 시트
        for method in method_names:
            matrix_df = _build_matrix(results, labels, method)
            matrix_df.to_excel(writer, sheet_name=method)
            _style_matrix(writer.sheets[method], len(labels))

        # 비교 목록 시트
        list_df = _build_list(results, method_names)
        list_df.to_excel(writer, sheet_name="비교_목록", index=False)
        _style_list(writer.sheets["비교_목록"], list_df, method_names)


# ------------------------------------------------------------------ #
# 요약 시트
# ------------------------------------------------------------------ #

_SEC_FILLS = {
    "date":  PatternFill("solid", fgColor="1F3864"),   # 진청
    "group": PatternFill("solid", fgColor="14401A"),   # 진초록
    "top":   PatternFill("solid", fgColor="3D1F00"),   # 진갈색
}
_SEC_FONT  = Font(bold=True, color="FFFFFF", size=11)
_ROW_ALT   = PatternFill("solid", fgColor="F2F2F2")


def _write_summary(
    writer,
    results: list[dict],
    method_names: list[str],
    site_groups: dict[str, list[str]],
    top_n: int,
) -> None:
    primary = method_names[0]
    score_map: dict[frozenset, float] = {
        frozenset([r["file_a"], r["file_b"]]): r[primary] for r in results
    }

    # 도메인 → 파일 목록
    domain_files: dict[str, list[str]] = {}
    for r in results:
        for f in (r["file_a"], r["file_b"]):
            d = _extract_domain(f)
            domain_files.setdefault(d, set()).add(f)
    domain_files = {d: sorted(fs) for d, fs in domain_files.items()}

    # -- 섹션 1: 날짜별 비교 --
    date_rows = []
    for domain, files in sorted(domain_files.items()):
        if len(files) < 2:
            continue
        files_s = sorted(files)
        for i in range(len(files_s)):
            for j in range(i + 1, len(files_s)):
                fa, fb = files_s[i], files_s[j]
                sc = score_map.get(frozenset([fa, fb]), 0.0)
                date_rows.append({"도메인": domain, "파일 A": fa, "파일 B": fb, primary: sc})

    # -- 섹션 2: 그룹 내 비교 --
    group_pairs: set[frozenset] = set()
    group_rows = []
    for gname, domains in sorted(site_groups.items()):
        # 해당 그룹 도메인의 모든 파일 수집
        group_files = []
        for d in domains:
            group_files.extend(domain_files.get(d, []))
        group_files = sorted(set(group_files))
        for i in range(len(group_files)):
            for j in range(i + 1, len(group_files)):
                fa, fb = group_files[i], group_files[j]
                pair = frozenset([fa, fb])
                # 날짜별 비교(섹션 1)와 중복 제거
                if any(pair == frozenset([r["파일 A"], r["파일 B"]]) for r in date_rows):
                    continue
                sc = score_map.get(pair, 0.0)
                group_pairs.add(pair)
                group_rows.append({"그룹": gname, "파일 A": fa, "파일 B": fb, primary: sc})

    # -- 섹션 3: 기타 상위 --
    excluded = {frozenset([r["파일 A"], r["파일 B"]]) for r in date_rows} | group_pairs
    top_rows = sorted(
        [r for r in results if frozenset([r["file_a"], r["file_b"]]) not in excluded],
        key=lambda r: r[primary],
        reverse=True,
    )[:top_n]

    # 시트 작성
    ws_name = "요약"
    dummy = pd.DataFrame([{"_": ""}])
    dummy.to_excel(writer, sheet_name=ws_name, index=False)
    ws = writer.sheets[ws_name]
    ws.delete_rows(1, ws.max_row)

    row = 1
    row = _sec_header(ws, row, "날짜별 비교 (같은 도메인, 다른 시점)", "date")
    row = _sec_columns(ws, row, ["도메인", "파일 A", "파일 B", primary])
    for i, r in enumerate(date_rows):
        row = _sec_data_row(ws, row, [r["도메인"], r["파일 A"], r["파일 B"], r[primary]], i)
    if not date_rows:
        row = _sec_data_row(ws, row, ["(없음)", "", "", ""], 0)
    row += 1

    row = _sec_header(ws, row, "그룹 내 비교 (같은 운영자 레이블)", "group")
    row = _sec_columns(ws, row, ["그룹", "파일 A", "파일 B", primary])
    group_rows_s = sorted(group_rows, key=lambda r: r[primary], reverse=True)
    for i, r in enumerate(group_rows_s):
        row = _sec_data_row(ws, row, [r["그룹"], r["파일 A"], r["파일 B"], r[primary]], i)
    if not group_rows_s:
        row = _sec_data_row(ws, row, ["(없음)", "", "", ""], 0)
    row += 1

    row = _sec_header(ws, row, f"기타 상위 유사도 Top {top_n}", "top")
    row = _sec_columns(ws, row, ["순위", "파일 A", "파일 B", primary])
    for i, r in enumerate(top_rows):
        row = _sec_data_row(ws, row, [i + 1, r["file_a"], r["file_b"], r[primary]], i)

    # 열 너비
    ws.column_dimensions["A"].width = 18
    ws.column_dimensions["B"].width = 36
    ws.column_dimensions["C"].width = 36
    ws.column_dimensions["D"].width = 16


def _sec_header(ws, row: int, title: str, sec: str) -> int:
    cell = ws.cell(row=row, column=1, value=title)
    cell.fill = _SEC_FILLS[sec]
    cell.font = _SEC_FONT
    cell.alignment = _CENTER
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=4)
    ws.row_dimensions[row].height = 22
    return row + 1


def _sec_columns(ws, row: int, cols: list[str]) -> int:
    for j, c in enumerate(cols, 1):
        cell = ws.cell(row=row, column=j, value=c)
        cell.fill = _HDR_FILL
        cell.font = _HDR_FONT
        cell.alignment = _CENTER
        cell.border = _BORDER
    return row + 1


def _sec_data_row(ws, row: int, values: list, idx: int) -> int:
    fill = _ROW_ALT if idx % 2 == 1 else PatternFill()
    for j, v in enumerate(values, 1):
        cell = ws.cell(row=row, column=j, value=v)
        cell.alignment = _CENTER
        cell.border = _BORDER
        if isinstance(v, float):
            cell.fill = PatternFill("solid", fgColor=_sim_color(v))
        else:
            cell.fill = fill
    return row + 1


# ------------------------------------------------------------------ #
# DataFrame 빌드
# ------------------------------------------------------------------ #

def _build_matrix(results: list[dict], labels: list[str], method: str) -> pd.DataFrame:
    n = len(labels)
    idx = {name: i for i, name in enumerate(labels)}
    mat = np.eye(n, dtype=float)
    for r in results:
        i, j = idx[r["file_a"]], idx[r["file_b"]]
        mat[i][j] = mat[j][i] = r[method]
    return pd.DataFrame(mat, index=labels, columns=labels).round(4)


def _build_list(results: list[dict], method_names: list[str]) -> pd.DataFrame:
    rows = [
        {"파일 A": r["file_a"], "파일 B": r["file_b"], **{m: r[m] for m in method_names}}
        for r in results
    ]
    return (
        pd.DataFrame(rows)
        .sort_values(method_names[0], ascending=False)
        .reset_index(drop=True)
    )


# ------------------------------------------------------------------ #
# 스타일 적용
# ------------------------------------------------------------------ #

def _style_matrix(ws, n: int) -> None:
    for col in range(1, n + 2):
        _hdr(ws.cell(row=1, column=col))
    for row in range(2, n + 2):
        _hdr(ws.cell(row=row, column=1))
        for col in range(2, n + 2):
            cell = ws.cell(row=row, column=col)
            cell.alignment = _CENTER
            cell.border = _BORDER
            if isinstance(cell.value, (int, float)):
                cell.fill = PatternFill("solid", fgColor=_sim_color(cell.value))
    ws.freeze_panes = "B2"
    ws.column_dimensions["A"].width = 32
    for col in range(2, n + 2):
        ws.column_dimensions[get_column_letter(col)].width = 14


def _style_list(ws, df: pd.DataFrame, method_names: list[str]) -> None:
    n_cols = len(df.columns)
    for col in range(1, n_cols + 1):
        _hdr(ws.cell(row=1, column=col))

    score_cols = {df.columns.get_loc(m) + 1 for m in method_names}
    for row in range(2, len(df) + 2):
        for col in range(1, n_cols + 1):
            cell = ws.cell(row=row, column=col)
            cell.alignment = _CENTER
            cell.border = _BORDER
            if col in score_cols and isinstance(cell.value, (int, float)):
                cell.fill = PatternFill("solid", fgColor=_sim_color(cell.value))
    ws.freeze_panes = "A2"
    ws.column_dimensions["A"].width = 32
    ws.column_dimensions["B"].width = 32
    for i in range(3, n_cols + 1):
        ws.column_dimensions[get_column_letter(i)].width = 18


def _hdr(cell) -> None:
    cell.fill = _HDR_FILL
    cell.font = _HDR_FONT
    cell.alignment = _CENTER
    cell.border = _BORDER


def _sim_color(val: float) -> str:
    val = max(0.0, min(1.0, float(val)))
    r = int(255 - val * (255 - 56))
    g = int(255 - val * (255 - 168))
    b = int(255 - val * (255 - 56))
    return f"{r:02X}{g:02X}{b:02X}"
