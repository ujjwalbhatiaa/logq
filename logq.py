#!/usr/bin/env python3
"""logq - query and analyse web server access logs from the command line.

Parses Apache / Nginx access logs in Common Log Format and Combined Log
Format:

    127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326
    127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 \
        "http://example.com/start" "Mozilla/5.0"

Filters (--status, --method, --path, --path-regex, --ip, --since, --until),
aggregates (--top-ips, --top-paths, --status-counts, --errors, --per-hour)
and output modes (--count, --json) make it the tool you reach for when
`grep` is not enough and spinning up a log pipeline is overkill.

Malformed lines are skipped with a warning count on stderr; logq never
crashes on bad input.

Only the Python standard library is used. No dependencies.

Exit codes: 0 on success (including zero matches), 1 for runtime problems
(unreadable file, broken pipe), 2 for bad flags or bad filter values.
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime

__version__ = "1.0.0"

# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0"
# 200 2326 "http://example.com/start" "Mozilla/5.0"
_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[^"]*)?" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?$'
)

_TIME_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",   # 10/Oct/2000:13:55:36 -0700 (log format)
    "%Y-%m-%d %H:%M:%S",      # 2000-10-10 13:55:36
    "%Y-%m-%dT%H:%M:%S",      # 2000-10-10T13:55:36
    "%Y-%m-%d",               # 2000-10-10 (start of day)
)


class LogqError(Exception):
    """A user-facing error: message is printed, exit code is non-zero."""


class Entry:
    """One parsed access-log line."""

    __slots__ = ("ip", "time", "method", "path", "status", "bytes",
                 "referrer", "agent", "raw")

    def __init__(self, ip, time, method, path, status, nbytes,
                 referrer, agent, raw):
        self.ip = ip
        self.time = time          # datetime, or None if unparseable
        self.method = method
        self.path = path
        self.status = status      # int
        self.bytes = nbytes       # int, 0 when the log says "-"
        self.referrer = referrer  # str or None (Common Log Format)
        self.agent = agent        # str or None (Common Log Format)
        self.raw = raw            # original line, verbatim

    def as_dict(self):
        return {
            "ip": self.ip,
            "time": self.time.isoformat() if self.time else None,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "bytes": self.bytes,
            "referrer": self.referrer,
            "agent": self.agent,
        }


def parse_timestamp(text):
    """Parse a log timestamp; return a datetime or None."""
    try:
        return datetime.strptime(text, _TIME_FORMATS[0])
    except ValueError:
        return None


def parse_time_arg(text):
    """Parse a --since/--until value; raise LogqError on bad input.

    Returns a naive datetime in the log's own wall-clock time, so a
    --since of 15:00 matches log lines stamped 15:xx whatever zone
    the log was written in.
    """
    text = text.strip()
    for fmt in _TIME_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=None)
    raise LogqError(
        "invalid time %r: expected YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, "
        "or a log timestamp like 10/Oct/2000:13:55:36 -0700" % text)


def parse_line(line):
    """Parse one log line; return an Entry or None if malformed."""
    raw = line.rstrip("\n")
    if not raw.strip():
        return None
    match = _LOG_RE.match(raw)
    if not match:
        return None
    groups = match.groupdict()
    try:
        status = int(groups["status"])
    except ValueError:
        return None
    nbytes = groups["bytes"]
    if nbytes == "-":
        nbytes = 0
    else:
        try:
            nbytes = int(nbytes)
        except ValueError:
            return None
    return Entry(
        ip=groups["ip"],
        time=parse_timestamp(groups["time"]),
        method=groups["method"],
        path=groups["path"],
        status=status,
        nbytes=nbytes,
        referrer=groups.get("referrer"),
        agent=groups.get("agent"),
        raw=raw,
    )


def parse_status_filter(text):
    """Validate a --status value: '404' or a class like '5xx'."""
    text = text.strip().lower()
    if re.fullmatch(r"[1-5]xx", text):
        return ("class", int(text[0]))
    if re.fullmatch(r"[1-5]\d\d", text):
        return ("exact", int(text))
    raise LogqError(
        "invalid --status %r: expected a status code like 404 or a "
        "class like 5xx" % text)


def _split_list(values):
    """Split repeated/comma-separated flag values into a flat list."""
    out = []
    for value in values or []:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


class Filters:
    """All active filters; an entry passes when every set filter matches."""

    def __init__(self, args):
        self.statuses = [parse_status_filter(s)
                         for s in _split_list(args.status)]
        self.methods = [m.upper() for m in _split_list(args.method)]
        self.paths = _split_list(args.path)
        self.path_regex = None
        if args.path_regex:
            try:
                self.path_regex = re.compile(args.path_regex)
            except re.error as exc:
                raise LogqError("invalid --path-regex: %s" % exc)
        self.ips = _split_list(args.ip)
        self.since = parse_time_arg(args.since) if args.since else None
        self.until = parse_time_arg(args.until) if args.until else None

    def matches(self, entry):
        if self.statuses:
            ok = False
            for kind, value in self.statuses:
                if kind == "exact" and entry.status == value:
                    ok = True
                elif kind == "class" and entry.status // 100 == value:
                    ok = True
            if not ok:
                return False
        if self.methods and entry.method.upper() not in self.methods:
            return False
        if self.paths and not any(p in entry.path for p in self.paths):
            return False
        if self.path_regex and not self.path_regex.search(entry.path):
            return False
        if self.ips and entry.ip not in self.ips:
            return False
        if self.since or self.until:
            if entry.time is None:
                return False
            # Compare wall-clock times: strip any zone so --since 15:00
            # matches log lines stamped 15:xx in the log's own clock.
            moment = entry.time.replace(tzinfo=None)
            if self.since and moment < self.since:
                return False
            if self.until and moment > self.until:
                return False
        return True


def top_counts(entries, key, limit):
    """Most common values of key(entry), as (value, count) pairs."""
    counts = Counter(key(entry) for entry in entries)
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ranked[:limit]


def status_counts(entries):
    """Count of entries per status code, most frequent first."""
    counts = Counter(entry.status for entry in entries)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def error_stats(entries):
    """4xx/5xx breakdown plus the overall error rate."""
    total = len(entries)
    client = sum(1 for e in entries if 400 <= e.status < 500)
    server = sum(1 for e in entries if 500 <= e.status < 600)
    errors = client + server
    return {
        "total": total,
        "errors": errors,
        "client_errors_4xx": client,
        "server_errors_5xx": server,
        "error_rate": (errors / total) if total else 0.0,
    }


def per_hour(entries):
    """Count of entries per hour, as (hour, count) pairs in time order."""
    counts = Counter()
    for entry in entries:
        if entry.time is None:
            continue
        counts[entry.time.strftime("%Y-%m-%d %H:00")] += 1
    return sorted(counts.items())


def read_entries(paths, warn):
    """Read entries from files (or stdin when paths is empty).

    Returns (entries, skipped). Malformed lines are counted, never fatal.
    """
    entries = []
    skipped = 0
    if not paths:
        lines = sys.stdin
        for line in lines:
            entry = parse_line(line)
            if entry is None:
                skipped += 1
            else:
                entries.append(entry)
        return entries, skipped
    for path in paths:
        try:
            handle = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            raise LogqError("cannot read %s: %s" % (path, exc.strerror or exc))
        with handle:
            for line in handle:
                entry = parse_line(line)
                if entry is None:
                    skipped += 1
                else:
                    entries.append(entry)
    return entries, skipped


def build_parser():
    parser = argparse.ArgumentParser(
        prog="logq",
        description="Query and analyse web server access logs "
                    "(Common and Combined Log Format).")
    parser.add_argument("files", nargs="*", metavar="FILE",
                        help="log file(s) to read; reads stdin if omitted")
    parser.add_argument("--status", action="append", default=[],
                        metavar="CODE",
                        help="only this status code (404) or class (5xx); "
                             "repeatable, comma-separated")
    parser.add_argument("--method", action="append", default=[],
                        metavar="METHOD",
                        help="only this HTTP method (GET); repeatable, "
                             "comma-separated")
    parser.add_argument("--path", action="append", default=[],
                        metavar="TEXT",
                        help="only paths containing TEXT; repeatable")
    parser.add_argument("--path-regex", metavar="REGEX",
                        help="only paths matching this regular expression")
    parser.add_argument("--ip", action="append", default=[],
                        metavar="IP",
                        help="only this client IP; repeatable, "
                             "comma-separated")
    parser.add_argument("--since", metavar="TIME",
                        help="only entries at or after TIME "
                             "(YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--until", metavar="TIME",
                        help="only entries at or before TIME")
    parser.add_argument("--top-ips", type=int, metavar="N",
                        help="show the N most frequent client IPs")
    parser.add_argument("--top-paths", type=int, metavar="N",
                        help="show the N most requested paths")
    parser.add_argument("--status-counts", action="store_true",
                        help="count entries per status code")
    parser.add_argument("--errors", action="store_true",
                        help="show 4xx/5xx counts and the error rate")
    parser.add_argument("--per-hour", action="store_true",
                        help="show a per-hour request histogram")
    parser.add_argument("--count", action="store_true",
                        help="print only how many entries matched")
    parser.add_argument("--json", action="store_true",
                        help="print output as JSON instead of plain text")
    parser.add_argument("--version", action="version",
                        version="logq " + __version__)
    return parser


def _positive_int(name, value):
    if value is not None and value <= 0:
        raise LogqError("--%s needs a positive number, got %d" % (name, value))


def format_aggregates(args, entries, as_json):
    """Render the requested aggregates; returns a list of output lines."""
    result = {}
    lines = []
    if args.top_ips is not None:
        rows = top_counts(entries, lambda e: e.ip, args.top_ips)
        result["top_ips"] = [{"ip": ip, "count": n} for ip, n in rows]
        lines.extend("%7d %s" % (n, ip) for ip, n in rows)
    if args.top_paths is not None:
        rows = top_counts(entries, lambda e: e.path, args.top_paths)
        result["top_paths"] = [{"path": p, "count": n} for p, n in rows]
        lines.extend("%7d %s" % (n, p) for p, n in rows)
    if args.status_counts:
        rows = status_counts(entries)
        result["status_counts"] = {str(s): n for s, n in rows}
        lines.extend("%7d %d" % (n, s) for s, n in rows)
    if args.errors:
        stats = error_stats(entries)
        result["errors"] = stats
        lines.append("total requests:   %d" % stats["total"])
        lines.append("4xx errors:       %d" % stats["client_errors_4xx"])
        lines.append("5xx errors:       %d" % stats["server_errors_5xx"])
        lines.append("error rate:       %.1f%%" % (stats["error_rate"] * 100))
    if args.per_hour:
        rows = per_hour(entries)
        result["per_hour"] = [{"hour": h, "count": n} for h, n in rows]
        lines.extend("%s  %d" % (h, n) for h, n in rows)
    if as_json:
        return [json.dumps(result)]
    return lines


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        _positive_int("top-ips", args.top_ips)
        _positive_int("top-paths", args.top_paths)
        filters = Filters(args)
        entries, skipped = read_entries(args.files, warn=True)
    except LogqError as exc:
        print("logq: error: %s" % exc, file=sys.stderr)
        return 2 if "invalid" in str(exc) or "needs a positive" in str(exc) \
            else 1
    if skipped:
        print("logq: warning: skipped %d malformed line(s)"
              % skipped, file=sys.stderr)
    matched = [e for e in entries if filters.matches(e)]
    has_aggregate = (args.top_ips is not None or args.top_paths is not None
                     or args.status_counts or args.errors or args.per_hour)
    try:
        if has_aggregate:
            out_lines = format_aggregates(args, matched, args.json)
        elif args.count:
            out_lines = [json.dumps({"count": len(matched)})
                         if args.json else str(len(matched))]
        elif args.json:
            out_lines = [json.dumps([e.as_dict() for e in matched])]
        else:
            out_lines = [e.raw for e in matched]
        for line in out_lines:
            print(line)
    except BrokenPipeError:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
