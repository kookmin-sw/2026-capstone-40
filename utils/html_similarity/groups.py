"""
같은 운영자로 레이블된 사이트 그룹 정의
키: 그룹명  /  값: 도메인 목록 (날짜·버전 접미사 제외)
"""

SITE_GROUPS: dict[str, list[str]] = {
    "linkkf":  ["linkkf.live",   "linkkf.tv"],
    "ohli24":  ["ohli24.net",    "ani.ohli24.com"],
    "ohli365": ["ohli365.org"],
    "anilife": ["anilife.app",   "anilife.live"],
    "newtoki": ["newtoki469.com"],
    "wfwf":    ["wfwf449.com"],
    "tkor":    ["tkor089.com",   "tkor115.com"],
    "youtube": ["youtube.com"],
}
