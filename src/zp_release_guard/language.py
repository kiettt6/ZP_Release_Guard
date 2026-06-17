import re
import unicodedata


VIETNAMESE_DIACRITICS = re.compile(
    r"[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễ"
    r"ìíịỉĩòóọỏõôồốộổỗơờớợởỡ"
    r"ùúụủũưừứựửữỳýỵỷỹđ"
    r"ÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄ"
    r"ÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠ"
    r"ÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ]"
)

VIETNAMESE_WORDS = {
    "anh",
    "ban",
    "bang",
    "bao",
    "bi",
    "can",
    "cau",
    "chao",
    "cho",
    "chua",
    "co",
    "cua",
    "duoc",
    "gi",
    "giup",
    "hoi",
    "khong",
    "kiem",
    "la",
    "loi",
    "minh",
    "nay",
    "neu",
    "phan",
    "sao",
    "sua",
    "tieng",
    "toi",
    "tra",
    "trong",
    "ung",
    "ve",
    "viet",
    "xin",
    "xem",
}

VIETNAMESE_RELEASE_WORDS = {
    "bank": ["ngan hang", "lien ket ngan hang"],
    "bug": ["loi", "fix loi", "sua loi"],
    "cashback": ["hoan tien", "cashback"],
    "impact": ["anh huong", "pham vi"],
    "ledger": ["so cai", "but toan", "hach toan"],
    "payment": ["thanh toan", "chi tra"],
    "refund": ["hoan tien", "refund"],
    "release": ["phat hanh", "release", "trien khai"],
    "topup": ["nap tien", "nap vi"],
    "voucher": ["voucher", "khuyen mai", "ma giam gia"],
}


def is_vietnamese_text(text: str) -> bool:
    if VIETNAMESE_DIACRITICS.search(text):
        return True

    tokens = re.findall(r"[a-zA-Z]+", text.lower())
    if not tokens:
        return False

    vietnamese_hits = sum(1 for token in tokens if token in VIETNAMESE_WORDS)
    return vietnamese_hits >= 3


def response_language_for(text: str) -> str:
    return "Vietnamese" if is_vietnamese_text(text) else "English"


def has_vietnamese_release_signal(text: str) -> bool:
    lowered = normalize_vietnamese_text(text.lower())
    return any(phrase in lowered for phrases in VIETNAMESE_RELEASE_WORDS.values() for phrase in phrases)


def normalize_vietnamese_text(text: str) -> str:
    normalized = unicodedata.normalize("NFD", text)
    stripped = "".join(char for char in normalized if unicodedata.category(char) != "Mn")
    return stripped.replace("đ", "d").replace("Đ", "D")


LATEX_SYMBOL_MAP = {
    # Right arrows
    "rightarrow": "→",
    "rightArrow": "→",
    "RightArrow": "→",
    "to": "→",
    "Rightarrow": "⇒",
    
    # Left arrows
    "leftarrow": "←",
    "leftArrow": "←",
    "LeftArrow": "←",
    "gets": "←",
    "Leftarrow": "⇐",
    
    # Bidirectional arrows
    "leftrightarrow": "↔",
    "leftRightArrow": "↔",
    "Leftrightarrow": "⇔",
    
    # Up/down arrows
    "uparrow": "↑",
    "downarrow": "↓",
    "updownarrow": "↕",
    
    # Comparison operators
    "leq": "≤",
    "le": "≤",
    "geq": "≥",
    "ge": "≥",
    "neq": "≠",
    "ne": "≠",
    "approx": "≈",
    
    # Math operators
    "times": "×",
    "div": "÷",
    "pm": "±",
    "cdot": "•",
    
    # Others
    "infty": "∞",
    "circ": "°",
}


def clean_latex_symbols(text: str) -> str:
    if not text:
        return text

    # Pattern for $ \command $
    pattern_dollars = re.compile(r"\$\s*\\([a-zA-Z]+)\s*\$")
    # Pattern for \command
    pattern_backslash = re.compile(r"\\([a-zA-Z]+)\b")

    def replace_match(match):
        cmd = match.group(1)
        return LATEX_SYMBOL_MAP.get(cmd, match.group(0))

    result = pattern_dollars.sub(replace_match, text)
    result = pattern_backslash.sub(replace_match, result)
    return result

