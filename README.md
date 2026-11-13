# logq

Query and analyse web server access logs from the command line — no
dependencies, pure Python standard library.

`logq` parses Apache / Nginx access logs in Common Log Format and Combined
Log Format, filters them, and answers the questions you actually ask about
a log file: which IPs hit you hardest, which paths 404, how bad the error
rate is, and when the traffic spiked. It is the tool you reach for when
`grep` is not enough and spinning up a log pipeline is overkill.

## Installation

No installation and no dependencies — Python 3.8+ is all it needs.

```sh
# Run it directly
python3 logq.py access.log

# Or make it executable and put it on your PATH
chmod +x logq.py
cp logq.py /usr/local/bin/logq
```

## Usage

```
logq [FILE ...] [--status CODE] [--method METHOD] [--path TEXT]
     [--path-regex REGEX] [--ip IP] [--since TIME] [--until TIME]
     [--top-ips N] [--top-paths N] [--status-counts] [--errors]
     [--per-hour] [--count] [--json]
```

- `FILE` — one or more log files to read. If omitted, `logq` reads stdin.
- `--status` — only a status code (`404`) or a class (`5xx`); repeatable,
  comma-separated.
- `--method` — only an HTTP method (`GET`); repeatable, comma-separated.
- `--path` — only paths containing the text; repeatable.
- `--path-regex` — only paths matching the regular expression.
- `--ip` — only a client IP; repeatable, comma-separated.
- `--since` / `--until` — only entries in the time range
  (`YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`, in the log's own clock).
- `--top-ips N` — the N most frequent client IPs.
- `--top-paths N` — the N most requested paths.
- `--status-counts` — count of entries per status code.
- `--errors` — 4xx/5xx counts and the overall error rate.
- `--per-hour` — requests per hour.
- `--count` — print only how many entries matched.
- `--json` — print output as JSON instead of plain text.

Malformed lines are skipped with a warning count on stderr; `logq` never
crashes on bad input. Exit codes: `0` on success (including zero matches),
`1` for runtime problems (unreadable file), `2` for bad flags or bad
filter values.

## Examples

Given `sample-access.log` (included in this repo):

```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326
203.0.113.7 - - [10/Oct/2000:14:02:11 -0700] "POST /api/login HTTP/1.1" 401 512 "http://example.com/" "Mozilla/5.0"
198.51.100.23 - - [10/Oct/2000:14:05:00 -0700] "GET /missing.png HTTP/1.1" 404 0 "-" "curl/8.0"
192.0.2.9 - - [10/Oct/2000:15:10:44 -0700] "GET /api/data HTTP/1.1" 500 128 "-" "python-requests/2.31"
127.0.0.1 - - [10/Oct/2000:15:11:00 -0700] "HEAD /ping HTTP/1.1" 204 - "-" "curl/8.0"
127.0.0.1 - - [10/Oct/2000:15:12:30 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "curl/8.0"
203.0.113.7 - - [10/Oct/2000:16:00:00 -0700] "GET /about HTTP/1.1" 301 0 "-" "Mozilla/5.0"
```

```sh
$ logq --top-ips 3 sample-access.log
      3 127.0.0.1
      2 203.0.113.7
      1 192.0.2.9

$ logq --status-counts sample-access.log
      2 200
      1 204
      1 301
      1 401
      1 404
      1 500

$ logq --errors sample-access.log
total requests:   7
4xx errors:       2
5xx errors:       1
error rate:       42.9%

$ logq --per-hour sample-access.log
2000-10-10 13:00  1
2000-10-10 14:00  2
2000-10-10 15:00  3
2000-10-10 16:00  1

$ logq --status 5xx --json sample-access.log
[{"ip": "192.0.2.9", "time": "2000-10-10T15:10:44-07:00", "method": "GET", "path": "/api/data", "status": 500, "bytes": 128, "referrer": "-", "agent": "python-requests/2.31"}]

$ logq --status 4xx --count sample-access.log
2

# Pipe it: count the GETs in the afternoon rush
$ cat sample-access.log | logq --method GET --since "2000-10-10 15:00:00" --count
3
```

## Running the tests

```sh
python3 -m pytest tests/ -q
```

69 tests cover parsing (both log formats, malformed lines, `-` byte
counts), every filter, every aggregate, CLI end-to-end runs via
subprocess, and the error cases (missing file, bad flags, bad regex,
bad time values, empty input).

## License

MIT — see [LICENSE](LICENSE).
