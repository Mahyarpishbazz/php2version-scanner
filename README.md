```
    ____     __  __    ____      _    __    ______    ____    _____    ____   ____     _   __
   / __ \   / / / /   / __ \    | |  / /   / ____/   / __ \  / ___/   /  _/  / __ \   / | / /
  / /_/ /  / /_/ /   / /_/ /    | | / /   / __/     / /_/ /  \__ \    / /   / / / /  /  |/ /
 / ____/  / __  /   / ____/     | |/ /   / /___    / _, _/  ___/ /  _/ /   / /_/ /  / /|  /
/_/      /_/ /_/   /_/          |___/   /_____/   /_/ |_|  /____/  /___/   \____/  /_/ |_/

   _____   ______    ___     _   __    _   __    ______    ____
  / ___/  / ____/   /   |   / | / /   / | / /   / ____/   / __ \
  \__ \  / /       / /| |  /  |/ /   /  |/ /   / __/     / /_/ /
 ___/ / / /___    / ___ | / /|  /   / /|  /   / /___    / _, _/
/____/  \____/   /_/  |_|/_/ |_/   /_/ |_/   /_____/   /_/ |_|
```

# php2version-scanner - PHP2Shell Patch Status Checker

![Build](https://img.shields.io/badge/Built%20with-Python-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Stars](https://img.shields.io/github/stars/Mahyarpishbazz/php2version-scanner.svg)
![Purpose](https://img.shields.io/badge/purpose-defensive-success)

> A non-intrusive checker for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")

Developed by [@Mahyarpishbazz](https://github.com/Mahyarpishbazz).

Both CVEs are critical pre-auth RCE bugs in PHP core (CVSS 4.0: 9.2), disclosed on Oct 21, 2026. This tool answers one question: **is my server patched?** It sends plain GET requests, reads the PHP version the server already discloses, and compares it with the fixed releases: **8.5.12**, **8.4.27**, **8.3.36** and **8.2.35**. No exploit payloads, nothing intrusive.

## Quick Start

Requires Python 3.10 or higher.

```
git clone https://github.com/Mahyarpishbazz/php2version-scanner.git --depth 1
cd php2version-scanner
pip install -r requirements.txt
python scanner.py
```

The same commands work on Linux, macOS and Windows (use `python3` instead of `python` if your system needs it).

Prefer a self-contained setup? On Linux/macOS, `./run.sh` does the same thing inside its own virtual environment (run `chmod +x run.sh` once first).

## Minimal Examples

```
python scanner.py                              # interactive: type your targets in
python scanner.py example.com 10.0.0.5         # scan one or more targets directly
python scanner.py targets.txt                  # scan a list (one target per line)
python scanner.py targets.txt -o report.csv    # custom report name (default: results.csv)
```

Targets can be domains, URLs or raw IPs, including internal ones (`192.168.1.10`, `10.0.0.5:8080`). No scheme means HTTPS, with an automatic HTTP retry if HTTPS is refused. See [targets.example.txt](targets.example.txt).

```
Checking 3 target(s)...

  https://example.com                      -> patched                   (8.4.27)
  https://old-site.example.org             -> vulnerable                (7.4.33)
  http://10.0.0.5                          -> unknown (no version header) (n/a) [WordPress 6.8.1]

Done. 1 likely-vulnerable target(s) found.
Full results written to: results.csv
```

## Results

| Status                        | Meaning                                                                       |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `patched`                     | Version is at or above the fix for its branch                                 |
| `vulnerable`                  | Version predates the fix (or the branch is EOL, e.g. 7.4)                     |
| `unknown-branch`              | Version found, but its branch isn't in the advisory table                     |
| `unknown (no version header)` | Server didn't disclose a version (or was unreachable, see the `error` column) |

Many servers hide their version on purpose, so `unknown` is common and expected. The tool would rather say "I don't know" than guess.

## How It Works

It requests `/`, `/wp-login.php`, `/xmlrpc.php` and `/wp-cron.php` (some setups strip the version header only from the homepage) and parses the `X-Powered-By` and `Server` headers. If no PHP version is found, it also tries to detect the WordPress core version, and only reports one when at least two independent sources agree (feed, meta tag, core assets).

## Limitations

This is a detection aid, not proof of exploitability. Treat `vulnerable` as high-confidence and `unknown` as needs-manual-check. For a definitive answer, check the server directly (`php -v`, hosting panel, SSH).

## Roadmap

- [ ] CIDR / IP-range input
- [ ] Sigma / Suricata detection rules
- [ ] Web dashboard for fleet-wide patch visibility

## Disclaimer

For defensive use only: scan your own infrastructure or systems you have permission to check.

## Contributing

Pull requests and feature requests are welcome.

## License

Copyright (c) 2026 Mahyar Pishbaz. Released under the [MIT License](LICENSE).
