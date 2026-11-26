"""비밀번호 금고지기 테스트. 실행:  pytest"""
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app as site  # noqa: E402


def crack_seconds(pw):
    guesses, _ = site.analyze(pw)
    return site.seconds(guesses, site.FAST)


# ---------------------------------------------------------------- 문자 종류 수
@pytest.mark.parametrize("pw, expected", [
    ("abc", 26),
    ("ABC", 26),
    ("123", 10),
    ("abcABC", 52),
    ("abc123", 36),
    ("aB3!", 95),
    ("안녕", 2350),
])
def test_cardinality_counts_only_the_types_used(pw, expected):
    assert site.cardinality(pw) == expected


# ---------------------------------------------------------------- 진단
@pytest.mark.parametrize("pw", ["password", "qwer1234", "qwer1234!", "P@ssw0rd", "123456", "iloveyou"])
def test_common_passwords_fall_in_under_a_minute(pw):
    assert crack_seconds(pw) < 60


@pytest.mark.parametrize("pw", ["dkssud", "tkfkdgo", "qlalfqjsgh", "dkssud12!", "안녕하세요123"])
def test_korean_words_are_caught(pw):
    """한글 단어를 영문 자판으로 치면 무작위처럼 보이지만 실제로는 흔하다."""
    _, reasons = site.analyze(pw)
    assert any("한국어 단어" in r["text"] for r in reasons)
    assert crack_seconds(pw) < 60


def test_random_password_is_strong_and_has_no_pattern():
    guesses, reasons = site.analyze("hG7#kq9!Zp2x")
    assert site.verdict(site.seconds(guesses, site.FAST))[1] == "강함"
    assert [r["text"] for r in reasons] == ["알려진 단어나 패턴이 발견되지 않았습니다"]


def test_random_part_uses_real_character_count():
    """zxcvbn은 무작위 글자를 10가지로만 세므로, 실제 문자 종류 수로 계산해야 한다."""
    pw = "kT7#mq2xLp"
    guesses, _ = site.analyze(pw)
    assert guesses >= site.cardinality(pw) ** len(pw)


def test_longer_random_password_takes_longer():
    assert crack_seconds("kT7#mq2xLpW4") > crack_seconds("kT7#mq2xLp") > crack_seconds("kT7#mq2x")


def test_short_password_gets_a_length_warning():
    _, reasons = site.analyze("kT7#mq2x")
    assert any("12자 이상" in r["text"] for r in reasons)


def test_very_long_password_does_not_crash():
    guesses, _ = site.analyze("x9#Qz" * 25)          # 125자: zxcvbn의 72자 한계를 넘는다
    assert guesses > 0
    assert site.time_text(site.seconds(guesses, site.FAST))


# ---------------------------------------------------------------- 시간과 판정
@pytest.mark.parametrize("s, expected", [
    (0.5, "1초 미만"),
    (1, "1초"),
    (90, "1분 30초"),
    (3600, "1시간"),
    (86400 * 3 + 3600 * 4, "3일 4시간"),
    (site.YEAR * 2, "2년"),
    (site.YEAR * 5e6, "약 500만 년"),
    (math.inf, "우주 나이의 수조 배 이상"),
])
def test_time_text(s, expected):
    assert site.time_text(s) == expected


@pytest.mark.parametrize("s, label", [
    (59, "즉시 뚫림"),
    (60, "매우 약함"),
    (86400, "약함"),
    (site.YEAR, "보통"),
    (site.YEAR * 100, "강함"),
])
def test_verdict_boundaries(s, label):
    assert site.verdict(s)[1] == label


def test_clock_cells():
    cells = site.clock(site.YEAR + 86400 * 2 + 3600 * 3 + 60 * 4 + 5)["cells"]
    assert [c["value"] for c in cells] == ["1", "2", "03", "04", "05"]
    assert site.clock(0.2) == {"single": "1초도 안 걸려요"}
    assert "single" in site.clock(site.YEAR * 1e9)


# ---------------------------------------------------------------- 생성
@pytest.mark.parametrize("length", [8, 20, 64])
def test_generated_password_has_requested_length_and_every_type(length):
    for _ in range(50):
        pw, pool = site.generate(length, ["lower", "upper", "digit", "symbol"], True)
        assert len(pw) == length
        assert pool == 81
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(c in site.SETS["symbol"] for c in pw)
        assert not set(pw) & site.AMBIGUOUS


def test_generate_respects_chosen_types():
    for _ in range(50):
        pw, pool = site.generate(16, ["lower", "digit"], False)
        assert pool == 36
        assert all(c in site.SETS["lower"] + site.SETS["digit"] for c in pw)


def test_generate_falls_back_to_lowercase_when_nothing_is_chosen():
    pw, pool = site.generate(12, [], False)
    assert pool == 26 and pw.islower()


def test_generated_passwords_differ():
    made = {site.generate(20, list(site.SETS), True)[0] for _ in range(200)}
    assert len(made) == 200


# ---------------------------------------------------------------- 웹 API
@pytest.fixture
def client():
    site._hits.clear()
    return site.app.test_client()


def test_page_and_static_files_are_served(client):
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_security_headers(client):
    headers = client.get("/").headers
    assert headers["Cache-Control"] == "no-store"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_check_api(client):
    data = client.post("/api/check", json={"password": "qwer1234"}).get_json()
    assert data["label"] == "즉시 뚫림"
    assert data["level"] == "crit"
    assert data["sample"] is None
    assert len(data["scenarios"]) == 4


def test_check_api_shows_example_when_empty(client):
    data = client.post("/api/check", json={"password": ""}).get_json()
    assert data["sample"] == site.SAMPLE


def test_check_api_survives_bad_input(client):
    assert client.post("/api/check", json={"password": 12345}).status_code == 200
    assert client.post("/api/check", data="not json", content_type="application/json").status_code == 200


def test_check_api_does_not_echo_the_password(client):
    """강한 비밀번호는 어떤 패턴에도 걸리지 않으므로 응답에 그 일부도 실려서는 안 된다."""
    secret = "hG7#kq9!Zp2x"
    body = client.post("/api/check", json={"password": secret}).get_data(as_text=True)
    assert secret not in body


def test_generate_api_clamps_length(client):
    assert client.post("/api/generate", json={"length": 3}).get_json()["length"] == 8
    assert client.post("/api/generate", json={"length": 999}).get_json()["length"] == 64
    assert client.post("/api/generate", json={"length": "abc"}).get_json()["length"] == 20


def test_generate_api_reports_randomness(client):
    data = client.post("/api/generate", json={"length": 20}).get_json()
    assert data["pool"] == 81
    assert data["bits"] == round(20 * math.log2(81))


def test_rate_limit(client):
    codes = [client.post("/api/check", json={"password": "a"}).status_code for _ in range(155)]
    assert codes[:150] == [200] * 150
    assert 429 in codes[150:]
