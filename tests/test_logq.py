"""Tests for logq: parsing, filters, aggregates, and the CLI end to end."""

import json
import subprocess
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import logq
from logq import (Entry, Filters, LogqError, error_stats, format_aggregates,
                  parse_line, parse_status_filter, parse_time_arg,
                  parse_timestamp, per_hour, read_entries, status_counts,
                  top_counts)

CLF = ('127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
       '"GET /index.html HTTP/1.0" 200 2326')
COMBINED = ('203.0.113.7 - - [10/Oct/2000:14:02:11 -0700] '
            '"POST /api/login HTTP/1.1" 401 512 '
            '"http://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"')
NOT_FOUND = ('198.51.100.23 - - [10/Oct/2000:14:05:00 -0700] '
             '"GET /missing.png HTTP/1.1" 404 0 "-" "curl/8.0"')
SERVER_ERROR = ('192.0.2.9 - - [10/Oct/2000:15:10:44 -0700] '
                '"GET /api/data HTTP/1.1" 500 128 "-" "python-requests/2.31"')
DASH_BYTES = ('127.0.0.1 - - [10/Oct/2000:15:11:00 -0700] '
              '"HEAD /ping HTTP/1.1" 204 - "-" "curl/8.0"')

SAMPLE_LINES = [CLF, COMBINED, NOT_FOUND, SERVER_ERROR, DASH_BYTES,
                ('127.0.0.1 - - [10/Oct/2000:15:12:30 -0700] '
                 '"GET /index.html HTTP/1.1" 200 2326 "-" "curl/8.0"'),
                ('203.0.113.7 - - [10/Oct/2000:16:00:00 -0700] '
                 '"GET /about HTTP/1.1" 301 0 "-" "Mozilla/5.0"')]

SAMPLE_TEXT = "\n".join(SAMPLE_LINES) + "\n"


def make_args(**overrides):
    """Build an argparse namespace the way build_parser() would."""
    import argparse
    args = argparse.Namespace(
        files=[], status=[], method=[], path=[], path_regex=None, ip=[],
        since=None, until=None, top_ips=None, top_paths=None,
        status_counts=False, errors=False, per_hour=False,
        count=False, json=False)
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def parse_all(lines):
    return [parse_line(line) for line in lines]


# ---------------------------------------------------------------- parsing

def test_parse_common_log_format():
    entry = parse_line(CLF)
    assert entry.ip == "127.0.0.1"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.status == 200
    assert entry.bytes == 2326
    assert entry.referrer is None
    assert entry.agent is None
    assert entry.time.year == 2000 and entry.time.month == 10
    assert entry.time.day == 10 and entry.time.hour == 13
    assert entry.time.minute == 55 and entry.time.second == 36
    assert entry.raw == CLF


def test_parse_combined_log_format():
    entry = parse_line(COMBINED)
    assert entry.ip == "203.0.113.7"
    assert entry.method == "POST"
    assert entry.path == "/api/login"
    assert entry.status == 401
    assert entry.bytes == 512
    assert entry.referrer == "http://example.com/"
    assert entry.agent == "Mozilla/5.0 (X11; Linux x86_64)"


def test_parse_dash_bytes_is_zero():
    assert parse_line(DASH_BYTES).bytes == 0


def test_parse_head_method_and_204():
    entry = parse_line(DASH_BYTES)
    assert entry.method == "HEAD"
    assert entry.status == 204


def test_parse_timestamp_valid():
    parsed = parse_timestamp("10/Oct/2000:13:55:36 -0700")
    assert parsed is not None
    assert (parsed.year, parsed.month, parsed.day) == (2000, 10, 10)
    assert (parsed.hour, parsed.minute, parsed.second) == (13, 55, 36)


def test_parse_timestamp_invalid_returns_none():
    assert parse_timestamp("not a timestamp") is None
    assert parse_timestamp("") is None


def test_parse_malformed_lines_return_none():
    assert parse_line("this is not a log line") is None
    assert parse_line("") is None
    assert parse_line("   ") is None
    assert parse_line("127.0.0.1 - - [10/Oct/2000:13:55:36 -0700]") is None
    assert parse_line("127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "
                      '"GET /x HTTP/1.1" abc 123') is None
    assert parse_line("127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "
                      '"GET /x HTTP/1.1" 200 xyz') is None


def test_parse_line_keeps_raw_verbatim():
    assert parse_line(SERVER_ERROR).raw == SERVER_ERROR


def test_entry_as_dict_round_trip():
    entry = parse_line(COMBINED)
    data = entry.as_dict()
    assert data["ip"] == "203.0.113.7"
    assert data["status"] == 401
    assert data["time"].startswith("2000-10-10T14:02:11")
    assert json.loads(json.dumps(data)) == data


def test_entry_as_dict_common_format_nulls():
    data = parse_line(CLF).as_dict()
    assert data["referrer"] is None
    assert data["agent"] is None


# ------------------------------------------------------- filter arguments

def test_parse_status_filter_exact():
    assert parse_status_filter("404") == ("exact", 404)
    assert parse_status_filter("200") == ("exact", 200)


def test_parse_status_filter_class():
    assert parse_status_filter("5xx") == ("class", 5)
    assert parse_status_filter("4XX") == ("class", 4)


def test_parse_status_filter_invalid():
    with pytest.raises(LogqError):
        parse_status_filter("99")
    with pytest.raises(LogqError):
        parse_status_filter("6xx")
    with pytest.raises(LogqError):
        parse_status_filter("oops")
    with pytest.raises(LogqError):
        parse_status_filter("")


def test_parse_time_arg_date_only():
    parsed = parse_time_arg("2000-10-10")
    assert (parsed.year, parsed.month, parsed.day) == (2000, 10, 10)
    assert parsed.tzinfo is None  # wall-clock time, like the log stamps


def test_parse_time_arg_datetime():
    parsed = parse_time_arg("2000-10-10 15:00:00")
    assert parsed.hour == 15


def test_parse_time_arg_log_timestamp():
    parsed = parse_time_arg("10/Oct/2000:13:55:36 -0700")
    assert parsed.hour == 13


def test_parse_time_arg_invalid():
    with pytest.raises(LogqError):
        parse_time_arg("yesterday")
    with pytest.raises(LogqError):
        parse_time_arg("10/10/2000")


# ---------------------------------------------------------------- filters

def test_filter_status_exact():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries if Filters(make_args(status=["404"])).matches(e)]
    assert [e.status for e in kept] == [404]


def test_filter_status_class_5xx():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries if Filters(make_args(status=["5xx"])).matches(e)]
    assert [e.status for e in kept] == [500]


def test_filter_status_class_4xx():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries if Filters(make_args(status=["4xx"])).matches(e)]
    assert sorted(e.status for e in kept) == [401, 404]


def test_filter_status_multiple_values():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries
            if Filters(make_args(status=["200", "301"])).matches(e)]
    assert sorted(e.status for e in kept) == [200, 200, 301]


def test_filter_method_case_insensitive():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries if Filters(make_args(method=["post"])).matches(e)]
    assert len(kept) == 1 and kept[0].path == "/api/login"


def test_filter_path_substring():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries if Filters(make_args(path=["/api"])).matches(e)]
    assert sorted(e.path for e in kept) == ["/api/data", "/api/login"]


def test_filter_path_regex():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries
            if Filters(make_args(path_regex=r"\.(png|html)$")).matches(e)]
    assert sorted(e.path for e in kept) == ["/index.html", "/index.html",
                                            "/missing.png"]


def test_filter_path_regex_invalid_raises():
    with pytest.raises(LogqError):
        Filters(make_args(path_regex="([broken"))


def test_filter_ip():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries
            if Filters(make_args(ip=["203.0.113.7"])).matches(e)]
    assert len(kept) == 2
    assert all(e.ip == "203.0.113.7" for e in kept)


def test_filter_since_until():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries if Filters(make_args(
        since="2000-10-10 15:00:00",
        until="2000-10-10 15:59:59")).matches(e)]
    assert sorted(e.path for e in kept) == ["/api/data", "/index.html",
                                            "/ping"]


def test_filter_since_only():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries
            if Filters(make_args(since="2000-10-10 16:00:00")).matches(e)]
    assert [e.path for e in kept] == ["/about"]


def test_filter_until_only():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries
            if Filters(make_args(until="2000-10-10 14:00:00")).matches(e)]
    assert [e.path for e in kept] == ["/index.html"]


def test_filter_combination_and_logic():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries if Filters(make_args(
        status=["2xx"], method=["GET"])).matches(e)]
    assert sorted(e.path for e in kept) == ["/index.html", "/index.html"]


def test_filter_no_filters_match_all():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries if Filters(make_args()).matches(e)]
    assert len(kept) == len(entries)


def test_filter_no_match_returns_empty():
    entries = parse_all(SAMPLE_LINES)
    kept = [e for e in entries
            if Filters(make_args(status=["418"])).matches(e)]
    assert kept == []


# -------------------------------------------------------------- aggregates

def test_top_ips():
    entries = parse_all(SAMPLE_LINES)
    assert top_counts(entries, lambda e: e.ip, 2) == [
        ("127.0.0.1", 3), ("203.0.113.7", 2)]


def test_top_ips_limit_one():
    entries = parse_all(SAMPLE_LINES)
    assert top_counts(entries, lambda e: e.ip, 1) == [("127.0.0.1", 3)]


def test_top_paths():
    entries = parse_all(SAMPLE_LINES)
    assert top_counts(entries, lambda e: e.path, 1) == [("/index.html", 2)]


def test_top_counts_tie_breaks_alphabetically():
    entries = parse_all([CLF, COMBINED])
    assert top_counts(entries, lambda e: e.ip, 2) == [
        ("127.0.0.1", 1), ("203.0.113.7", 1)]


def test_status_counts():
    entries = parse_all(SAMPLE_LINES)
    assert status_counts(entries) == [
        (200, 2), (204, 1), (301, 1), (401, 1), (404, 1), (500, 1)]


def test_error_stats():
    entries = parse_all(SAMPLE_LINES)
    stats = error_stats(entries)
    assert stats["total"] == 7
    assert stats["client_errors_4xx"] == 2
    assert stats["server_errors_5xx"] == 1
    assert stats["errors"] == 3
    assert abs(stats["error_rate"] - 3 / 7) < 1e-9


def test_error_stats_empty_input():
    stats = error_stats([])
    assert stats == {"total": 0, "errors": 0, "client_errors_4xx": 0,
                     "server_errors_5xx": 0, "error_rate": 0.0}


def test_per_hour():
    entries = parse_all(SAMPLE_LINES)
    assert per_hour(entries) == [
        ("2000-10-10 13:00", 1), ("2000-10-10 14:00", 2),
        ("2000-10-10 15:00", 3), ("2000-10-10 16:00", 1)]


def test_per_hour_empty_input():
    assert per_hour([]) == []


def test_status_counts_empty_input():
    assert status_counts([]) == []


# ------------------------------------------------------------------- reading

def test_read_entries_skips_malformed(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(SAMPLE_TEXT + "garbage line\n\nanother bad one\n")
    entries, skipped = read_entries([str(log)], warn=True)
    assert len(entries) == 7
    assert skipped == 3  # garbage line, blank line, bad line


def test_read_entries_missing_file():
    with pytest.raises(LogqError):
        read_entries(["/nonexistent/nope.log"], warn=True)


def test_read_entries_stdin(monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(SAMPLE_TEXT + "junk\n"))
    entries, skipped = read_entries([], warn=True)
    assert len(entries) == 7
    assert skipped == 1


# ----------------------------------------------------------------------- CLI

def run_cli(args, input_text=None):
    return subprocess.run(
        [sys.executable, "logq.py"] + args,
        input=input_text, capture_output=True, text=True,
        cwd=__file__.rsplit("/", 2)[0])


@pytest.fixture
def sample_log(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(SAMPLE_TEXT + "this line is malformed\n")
    return str(log)


def test_cli_prints_matching_lines(sample_log):
    result = run_cli([sample_log])
    assert result.returncode == 0
    assert result.stdout.count("\n") == 7
    assert "skipped 1 malformed line" in result.stderr


def test_cli_status_filter(sample_log):
    result = run_cli(["--status", "404", sample_log])
    assert result.returncode == 0
    assert "/missing.png" in result.stdout
    assert "/index.html" not in result.stdout


def test_cli_status_class_and_method(sample_log):
    result = run_cli(["--status", "2xx", "--method", "GET", sample_log])
    assert result.returncode == 0
    assert result.stdout.count("/index.html") == 2
    assert "/ping" not in result.stdout


def test_cli_count(sample_log):
    result = run_cli(["--status", "4xx", "--count", sample_log])
    assert result.returncode == 0
    assert result.stdout.strip() == "2"


def test_cli_count_zero_matches(sample_log):
    result = run_cli(["--status", "418", "--count", sample_log])
    assert result.returncode == 0
    assert result.stdout.strip() == "0"


def test_cli_json_lines(sample_log):
    result = run_cli(["--status", "500", "--json", sample_log])
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["path"] == "/api/data"
    assert data[0]["status"] == 500


def test_cli_top_ips(sample_log):
    result = run_cli(["--top-ips", "2", sample_log])
    assert result.returncode == 0
    lines = result.stdout.strip().splitlines()
    assert lines[0].strip().startswith("3 127.0.0.1")
    assert lines[1].strip().startswith("2 203.0.113.7")


def test_cli_top_paths_json(sample_log):
    result = run_cli(["--top-paths", "1", "--json", sample_log])
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["top_paths"] == [{"path": "/index.html", "count": 2}]


def test_cli_status_counts(sample_log):
    result = run_cli(["--status-counts", sample_log])
    assert result.returncode == 0
    assert "2 200" in result.stdout
    assert "1 500" in result.stdout


def test_cli_errors(sample_log):
    result = run_cli(["--errors", sample_log])
    assert result.returncode == 0
    assert "4xx errors:       2" in result.stdout
    assert "5xx errors:       1" in result.stdout
    assert "error rate:       42.9%" in result.stdout


def test_cli_per_hour(sample_log):
    result = run_cli(["--per-hour", sample_log])
    assert result.returncode == 0
    assert "2000-10-10 15:00  3" in result.stdout
    assert "2000-10-10 13:00  1" in result.stdout


def test_cli_stdin():
    result = run_cli(["--status", "200", "--count"], input_text=SAMPLE_TEXT)
    assert result.returncode == 0
    assert result.stdout.strip() == "2"


def test_cli_empty_stdin():
    result = run_cli(["--count"], input_text="")
    assert result.returncode == 0
    assert result.stdout.strip() == "0"


def test_cli_missing_file():
    result = run_cli(["/no/such/file.log"])
    assert result.returncode == 1
    assert "cannot read" in result.stderr


def test_cli_bad_status_value(sample_log):
    result = run_cli(["--status", "banana", sample_log])
    assert result.returncode == 2
    assert "invalid --status" in result.stderr


def test_cli_bad_flag():
    result = run_cli(["--nonsense"])
    assert result.returncode == 2


def test_cli_bad_regex(sample_log):
    result = run_cli(["--path-regex", "([oops", sample_log])
    assert result.returncode == 2
    assert "invalid --path-regex" in result.stderr


def test_cli_bad_since(sample_log):
    result = run_cli(["--since", "yesterday", sample_log])
    assert result.returncode == 2
    assert "invalid time" in result.stderr


def test_cli_bad_top_ips(sample_log):
    result = run_cli(["--top-ips", "0", sample_log])
    assert result.returncode == 2
    assert "positive number" in result.stderr


def test_cli_path_regex_end_to_end(sample_log):
    result = run_cli(["--path-regex", r"^/api/", "--count", sample_log])
    assert result.returncode == 0
    assert result.stdout.strip() == "2"


def test_cli_since_until_end_to_end(sample_log):
    result = run_cli(["--since", "2000-10-10 15:00:00",
                      "--until", "2000-10-10 15:59:59",
                      "--count", sample_log])
    assert result.returncode == 0
    assert result.stdout.strip() == "3"


def test_cli_version():
    result = run_cli(["--version"])
    assert result.returncode == 0
    assert result.stdout.strip() == "logq 1.0.0"


def test_cli_multiple_files(tmp_path):
    first = tmp_path / "a.log"
    second = tmp_path / "b.log"
    first.write_text(CLF + "\n")
    second.write_text(NOT_FOUND + "\n")
    result = run_cli(["--count", str(first), str(second)])
    assert result.returncode == 0
    assert result.stdout.strip() == "2"


def test_cli_no_matches_prints_nothing(sample_log):
    result = run_cli(["--ip", "10.9.9.9", sample_log])
    assert result.returncode == 0
    assert result.stdout == ""
