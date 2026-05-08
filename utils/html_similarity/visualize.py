"""
HTML 유사도 시각화

매칭된 서브트리를 GradCAM 스타일로 하이라이트:
  빨강  — 텍스트 Jaccard 높음 (구조+내용 일치)
  파랑  — 구조는 일치하지만 텍스트 다름
  회색  — 매칭 안 된 영역

출력: output/viz/compare__A__vs__B.html  (iframe 양분할 비교 페이지)
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent))

from utils.html_similarity.preprocessor import load, parse
from utils.html_similarity.methods.shape_content import _build_info, _subtree_ids, _tokenize, _jaccard, MIN_SIZE


# ------------------------------------------------------------------ #
# 매칭 — shape_content_v1 과 동일한 (Jaccard, size) 우선 정렬
# ------------------------------------------------------------------ #

def _greedy_match_full(info_a: dict, info_b: dict) -> list[dict]:
    shapes_a: dict = defaultdict(list)
    shapes_b: dict = defaultdict(list)
    for nid, d in info_a.items():
        if d["size"] >= MIN_SIZE:
            shapes_a[d["shape"]].append(nid)
    for nid, d in info_b.items():
        if d["size"] >= MIN_SIZE:
            shapes_b[d["shape"]].append(nid)

    candidates = []
    for shape in set(shapes_a) & set(shapes_b):
        for nid_a in shapes_a[shape]:
            text_a = info_a[nid_a]["node"].get_text(separator=" ", strip=True)
            words_a = _tokenize(text_a)
            sz_a = info_a[nid_a]["size"]
            for nid_b in shapes_b[shape]:
                words_b = _tokenize(info_b[nid_b]["node"].get_text(separator=" ", strip=True))
                jac = _jaccard(words_a, words_b)
                sz_b = info_b[nid_b]["size"]
                candidates.append((jac, sz_a + sz_b, nid_a, sz_a, nid_b, sz_b))
    candidates.sort(reverse=True)

    covered_a: set[int] = set()
    covered_b: set[int] = set()
    matches = []
    for jac, _, nid_a, sz_a, nid_b, sz_b in candidates:
        if nid_a in covered_a or nid_b in covered_b:
            continue
        covered_a.update(_subtree_ids(nid_a, info_a))
        covered_b.update(_subtree_ids(nid_b, info_b))
        matches.append({
            "nid_a": nid_a, "nid_b": nid_b,
            "size_a": sz_a, "size_b": sz_b,
            "jaccard": jac,
        })
    return matches


# ------------------------------------------------------------------ #
# 색상 매핑 (GradCAM: 높음=빨강, 낮음=파랑)
# ------------------------------------------------------------------ #

def _heatmap_css(j: float) -> tuple[str, str]:
    hue = int((1.0 - j) * 240)   # 0→빨강, 240→파랑
    return f"hsl({hue},90%,42%)", f"hsla({hue},90%,88%,0.55)"


# ------------------------------------------------------------------ #
# 하이라이트 주입
# ------------------------------------------------------------------ #

_LEGEND = """
<style id="__sim_viz__">
[data-sim-match]{{
  cursor:pointer;
  transition: outline .1s;
}}
[data-sim-match]:hover{{
  filter: brightness(.92);
}}
#__sim_legend__{{
  position:fixed; top:12px; right:12px; z-index:2147483647;
  background:rgba(255,255,255,.96); border:1px solid #bbb;
  border-radius:8px; padding:10px 14px; font:12px/1.5 monospace;
  box-shadow:0 2px 10px rgba(0,0,0,.25); min-width:170px;
  pointer-events:none;
}}
#__sim_legend__ h4{{margin:0 0 5px;font-size:13px;}}
.sbar{{height:12px;border-radius:3px;
  background:linear-gradient(to right,hsl(240,90%,88%),hsl(120,90%,88%),hsl(0,90%,88%));
  border:1px solid #ccc;margin-bottom:2px;}}
.slbl{{display:flex;justify-content:space-between;font-size:10px;color:#666;}}
</style>
<div id="__sim_legend__">
  <h4>유사도 히트맵</h4>
  <div class="sbar"></div>
  <div class="slbl"><span>구조만</span><span>구조+내용</span></div>
  <hr style="margin:5px 0;border-color:#ddd">
  <div>매칭 서브트리: <b>{n}</b>개</div>
  <div style="font-size:10px;color:#888;margin-top:3px;">hover → tooltip</div>
</div>
"""


def _inject(soup, info: dict, matches: list[dict], side: str) -> str:
    nid_key = f"nid_{side}"

    for i, m in enumerate(matches):
        nid  = m[nid_key]
        node = info[nid]["node"]
        j    = m["jaccard"]
        border, bg = _heatmap_css(j)

        prev = node.get("style", "") or ""
        node["style"] = (
            f"{prev}; outline:3px solid {border} !important;"
            f"background-color:{bg} !important;"
            f"position:relative !important;"
        )
        node["data-sim-match"] = str(i)
        node["title"] = (
            f"Match #{i}  |  Jaccard={j:.3f}"
            f"  |  size={m[f'size_{side}']}"
        )

    legend_html = _LEGEND.format(n=len(matches))
    target = soup.find("body") or soup
    target.append(BeautifulSoup(legend_html, "html.parser"))
    return str(soup)


# ------------------------------------------------------------------ #
# 공개 API
# ------------------------------------------------------------------ #

def visualize(
    path_a: str | Path,
    path_b: str | Path,
    out_dir: str | Path = "output/viz",
) -> Path:
    path_a, path_b = Path(path_a), Path(path_b)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    name_a, name_b = path_a.name, path_b.name
    print(f"로드 중: {name_a}, {name_b}")

    soup_a = parse(load(str(path_a)))
    soup_b = parse(load(str(path_b)))

    info_a = _build_info(soup_a)
    info_b = _build_info(soup_b)
    matches = _greedy_match_full(info_a, info_b)

    if not matches:
        print("매칭된 서브트리 없음")
        return None

    # 점수 요약 (shape_content_v1: 텍스트 pool Jaccard)
    pool_a: set[str] = set()
    pool_b: set[str] = set()
    for m in matches:
        pool_a.update(_tokenize(info_a[m["nid_a"]]["node"].get_text(" ", True)))
        pool_b.update(_tokenize(info_b[m["nid_b"]]["node"].get_text(" ", True)))
    score = _jaccard(pool_a, pool_b)
    print(f"매칭 {len(matches)}쌍  |  shape_content_v1={score:.4f}")
    for m in sorted(matches, key=lambda x: -x["jaccard"])[:5]:
        print(f"  Jac={m['jaccard']:.3f}  size=({m['size_a']},{m['size_b']})")

    # 하이라이트 저장
    hi_a = out_dir / f"hi_{name_a}"
    hi_b = out_dir / f"hi_{name_b}"
    hi_a.write_text(_inject(soup_a, info_a, matches, "a"), encoding="utf-8", errors="replace")
    hi_b.write_text(_inject(soup_b, info_b, matches, "b"), encoding="utf-8", errors="replace")

    # 양분할 비교 페이지
    stem_a = name_a.replace(".html", "").replace(".htm", "")
    stem_b = name_b.replace(".html", "").replace(".htm", "")
    comp = out_dir / f"compare__{stem_a}__vs__{stem_b}.html"
    comp.write_text(_comparison_page(name_a, name_b, len(matches), score), encoding="utf-8")

    print(f"\n비교 페이지: {comp.resolve()}")
    return comp


def _comparison_page(name_a: str, name_b: str, n: int, score: float) -> str:
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>{name_a} vs {name_b}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:sans-serif;background:#111;}}
.hdr{{display:flex;align-items:center;gap:16px;padding:7px 16px;
      background:#222;color:#ddd;font-size:12px;border-bottom:1px solid #444;}}
.hdr strong{{font-size:14px;color:#8cf;}}
.hdr .score{{color:#fa8;font-weight:bold;}}
.frames{{display:flex;height:calc(100vh - 34px);}}
.pane{{flex:1;display:flex;flex-direction:column;border-right:1px solid #444;}}
.pane:last-child{{border-right:none;}}
.lbl{{padding:4px 10px;background:#1e1e1e;color:#aaa;
      font:11px monospace;border-bottom:1px solid #333;}}
iframe{{flex:1;border:none;background:#fff;}}
</style>
</head>
<body>
<div class="hdr">
  <strong>HTML 유사도 시각화</strong>
  <span>매칭 서브트리 {n}쌍</span>
  <span class="score">shape_content = {score:.4f}</span>
  <span style="margin-left:auto;color:#666;">빨강=내용 일치 · 파랑=구조만 일치</span>
</div>
<div class="frames">
  <div class="pane">
    <div class="lbl">{name_a}</div>
    <iframe src="hi_{name_a}"></iframe>
  </div>
  <div class="pane">
    <div class="lbl">{name_b}</div>
    <iframe src="hi_{name_b}"></iframe>
  </div>
</div>
</body>
</html>"""


# ------------------------------------------------------------------ #
# 스크린샷 리포트
# ------------------------------------------------------------------ #

_HEADER_H   = 100   # px
_SHOT_W     = 1280  # 각 사이트 뷰포트 너비
_SHOT_H     = 900   # 뷰포트 높이 (full_page=True 이므로 실제 캡처는 더 길 수 있음)
_MAX_CROP_H = 4000  # 너무 긴 페이지 자르기


def make_report(
    path_a: str | Path,
    path_b: str | Path,
    out_dir: str | Path = "output/viz",
) -> Path:
    """
    하이라이트된 HTML을 Playwright 로 스크린샷 → PIL 로 합성
    상단: 사이트명 + 유사도  /  하단: 두 캡처 이미지 나란히
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        raise RuntimeError("pip install pillow")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError("pip install playwright && playwright install chromium")

    import io

    path_a, path_b = Path(path_a), Path(path_b)
    out_dir = Path(out_dir)

    # 1. 하이라이트 HTML 생성 (hi_*.html)
    name_a, name_b = path_a.name, path_b.name
    hi_a = out_dir / f"hi_{name_a}"
    hi_b = out_dir / f"hi_{name_b}"

    if not hi_a.exists() or not hi_b.exists():
        visualize(path_a, path_b, out_dir)

    # 유사도 점수 재계산
    soup_a = parse(load(str(path_a)))
    soup_b = parse(load(str(path_b)))
    info_a = _build_info(soup_a)
    info_b = _build_info(soup_b)
    matches = _greedy_match_full(info_a, info_b)
    if matches:
        pool_a: set[str] = set()
        pool_b: set[str] = set()
        for m in matches:
            pool_a.update(_tokenize(info_a[m["nid_a"]]["node"].get_text(" ", True)))
            pool_b.update(_tokenize(info_b[m["nid_b"]]["node"].get_text(" ", True)))
        score = _jaccard(pool_a, pool_b)
    else:
        score = 0.0

    # 2. Playwright 스크린샷
    print("스크린샷 촬영 중...")
    shots = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": _SHOT_W, "height": _SHOT_H})
        page = ctx.new_page()
        for label, hi_path in [("a", hi_a), ("b", hi_b)]:
            url = hi_path.resolve().as_uri()
            page.goto(url, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(1500)
            try:
                raw = page.screenshot(full_page=True, timeout=60000)
            except Exception:
                raw = page.screenshot(full_page=False, timeout=60000)
            img = Image.open(io.BytesIO(raw)).convert("RGB")
            if img.height > _MAX_CROP_H:
                img = img.crop((0, 0, img.width, _MAX_CROP_H))
            shots[label] = img
            print(f"  {hi_path.name}: {img.width}×{img.height}")
        browser.close()

    img_a, img_b = shots["a"], shots["b"]

    # 3. 두 이미지를 같은 높이로 맞추기 (짧은 쪽에 흰 여백)
    body_h = max(img_a.height, img_b.height)
    canvas_a = Image.new("RGB", (img_a.width, body_h), "#f5f5f5")
    canvas_b = Image.new("RGB", (img_b.width, body_h), "#f5f5f5")
    canvas_a.paste(img_a, (0, 0))
    canvas_b.paste(img_b, (0, 0))

    sep = 4  # 구분선 너비
    total_w = canvas_a.width + sep + canvas_b.width

    # 4. 헤더 그리기
    HDR_BG   = (18,  24,  42)
    HDR_TXT  = (200, 220, 255)
    SCORE_CLR = _score_color(score)

    header = Image.new("RGB", (total_w, _HEADER_H), HDR_BG)
    draw   = ImageDraw.Draw(header)

    font_lg, font_md, font_sm = _load_fonts(28, 18, 13)

    # 사이트명
    label_text = f"{name_a}   vs   {name_b}"
    draw.text((24, 14), label_text, font=font_md, fill=HDR_TXT)

    # 유사도
    score_text = f"similarity  {score:.4f}"
    sw = draw.textlength(score_text, font=font_lg)
    draw.text((total_w - sw - 24, 10), score_text, font=font_lg, fill=SCORE_CLR)

    # 매칭 서브트리 수
    sub_text = f"matched subtrees: {len(matches)}  |  red=content match  blue=structure only"
    draw.text((24, 66), sub_text, font=font_sm, fill=(120, 140, 180))

    # 컬럼 레이블
    col_lbl_h = 28
    col_bar   = Image.new("RGB", (total_w, col_lbl_h), (28, 32, 52))
    cdraw     = ImageDraw.Draw(col_bar)
    cdraw.text((12,  6), name_a, font=font_sm, fill=(160, 200, 255))
    cdraw.text((canvas_a.width + sep + 12, 6), name_b, font=font_sm, fill=(160, 200, 255))

    # 5. 합성
    body = Image.new("RGB", (total_w, body_h), (17, 17, 17))
    body.paste(canvas_a, (0, 0))
    body.paste(Image.new("RGB", (sep, body_h), (50, 50, 60)), (canvas_a.width, 0))
    body.paste(canvas_b, (canvas_a.width + sep, 0))

    final_h = _HEADER_H + col_lbl_h + body_h
    final   = Image.new("RGB", (total_w, final_h))
    final.paste(header,  (0, 0))
    final.paste(col_bar, (0, _HEADER_H))
    final.paste(body,    (0, _HEADER_H + col_lbl_h))

    # 6. 저장
    stem_a = name_a.replace(".html", "").replace(".htm", "")
    stem_b = name_b.replace(".html", "").replace(".htm", "")
    out_path = out_dir / f"report__{stem_a}__vs__{stem_b}.png"
    final.save(out_path, optimize=True)
    print(f"\n리포트 저장: {out_path.resolve()}")
    return out_path


def _score_color(score: float) -> tuple[int, int, int]:
    if score >= 0.3:
        return (80, 220, 120)   # 초록 (높음)
    if score >= 0.1:
        return (255, 190, 60)   # 주황 (중간)
    return (180, 180, 200)      # 회색 (낮음)


def _load_fonts(lg: int, md: int, sm: int):
    from PIL import ImageFont
    candidates = [
        "C:/Windows/Fonts/malgun.ttf",    # 맑은 고딕
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/segoeui.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return (
                ImageFont.truetype(path, lg),
                ImageFont.truetype(path, md),
                ImageFont.truetype(path, sm),
            )
    default = ImageFont.load_default()
    return default, default, default


# ------------------------------------------------------------------ #
# CLI
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("file_a")
    p.add_argument("file_b")
    p.add_argument("--out", default="output/viz")
    p.add_argument("--report", action="store_true", help="PNG 리포트 생성")
    args = p.parse_args()

    if args.report:
        make_report(args.file_a, args.file_b, args.out)
    else:
        visualize(args.file_a, args.file_b, args.out)
