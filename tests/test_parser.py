from src.parser import parse_line


def test_parser_valid_common_log():
    line = '127.0.0.1 - - [10/Mar/2026:10:00:00 +0000] "GET /index.php HTTP/1.1" 200 123'
    result = parse_line(line)

    assert result is not None
    assert result["ip"] == "127.0.0.1"
    assert result["method"] == "GET"
    assert result["path"] == "/index.php"
    assert result["status"] == 200

def test_parser_valid_combined_log():
    line = ('192.168.1.1 - - [10/Mar/2026:10:00:00 +0000] '
            '"POST /login HTTP/1.1" 401 512 '
            '"https://example.com" "Mozilla/5.0"')
    result = parse_line(line)

    assert result is not None
    assert result["ip"] == "192.168.1.1"
    assert result["method"] == "POST"
    assert result["path"] == "/login"
    assert result["status"] == 401
    assert result["user_agent"] == "Mozilla/5.0"
    assert result["referer"] == "https://example.com"

def test_parser_invalid_line():
    line = "this is not a log"
    result = parse_line(line)

    assert result is None