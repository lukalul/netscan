# netscan

A small, dependency-free multi-threaded TCP port scanner written in Python. It
takes a single IP, hostname, or CIDR range, probes ports concurrently, optionally
grabs service banners, and prints results as a table, JSON, or CSV.

## Install

netscan runs on the Python standard library alone (Python 3.9+). Clone the repo
and run it in place, or install it to get a `netscan` command on your PATH:

```
git clone https://github.com/lukalul/netscan.git
cd netscan
python cli.py --help    # run in place
pip install .           # or install the `netscan` command
```

For development, install the test extra and run pytest:

```
pip install -e ".[dev]"
pytest
```

## Usage

Scan the 1000 most common ports on a host (the default):

```
$ python cli.py 127.0.0.1
HOST       PORT  STATE  SERVICE
---------  ----  -----  ------------
127.0.0.1  135   open   epmap
127.0.0.1  445   open   microsoft-ds

2 open port(s) found.
```

Scan an explicit port range with banner grabbing enabled:

```
$ python cli.py 127.0.0.1 -p 8080 --banner
HOST       PORT  STATE  SERVICE  BANNER
---------  ----  -----  -------  ----------------------------
127.0.0.1  8080  open   -        SimpleHTTP/0.6 Python/3.14.6

1 open port(s) found.
```

Scan a CIDR range and emit JSON for further processing:

```
$ python cli.py 127.0.0.1 -p 135,445 -o json
[
  {
    "host": "127.0.0.1",
    "port": 135,
    "state": "open",
    "service": "epmap",
    "banner": ""
  }
]
```

Tune concurrency and timeout, and export CSV:

```
$ python cli.py 10.0.0.0/24 -p 22,80,443 --threads 200 --timeout 0.5 -o csv > results.csv
```

### Options

| Flag              | Default    | Description                                          |
| ----------------- | ---------- | ---------------------------------------------------- |
| `-p, --ports`     | `top-1000` | `80`, `22,80,443`, `20-25`, or `top-1000`            |
| `--threads`       | `100`      | worker threads                                       |
| `--timeout`       | `1.0`      | per-connection timeout in seconds                    |
| `--banner`        | off        | grab service banners on open ports                   |
| `-o, --output`    | `table`    | `table`, `json`, or `csv`                            |
| `-v, --verbose`   | off        | debug logging on stderr                              |

Exit codes: `0` success, `1` runtime error (e.g. unresolvable host), `2`
invalid arguments, `130` interrupted with Ctrl-C.

## Why I built this

I kept reaching for `nmap` for the same trivial task — "is this port open on
this box?" — and wanted something I could read end to end and trust. Building my
own scanner forced me to actually understand connect scans, thread-pool
back-pressure, socket timeouts, and banner parsing instead of treating them as
magic. It is deliberately small and stdlib-only so it fits in your head.

## Legal and ethical use

Port scanning hosts you do not own or lack written authorization to test can be
illegal in many jurisdictions and violates the acceptable-use policy of most
networks. Only scan systems you own or have explicit permission to assess. You
are responsible for how you use this tool.
