from src.parser import parse_line

def test_parser_valid_loop():
    line = '127.0.0.1 - - [10/Mar/2026:10:00:00 +0000] "GET /index.php HTTP/1.1" 200 123'
    result = parse_line(line)

    assert result is not None
    assert result["ip"] == "127.0.0.1"
    assert result["method"] == "GET"
    assert result["path"] == "/index.php"
    assert result["status"] == 200

def test_parser_invalid_loop():
    line = "this is not a log"
    result = parse_line(line)

    assert result is None