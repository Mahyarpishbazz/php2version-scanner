#!/usr/bin/env python3
"""
A small tool I put together after the PHP2Shell CVEs dropped
(CVE-2026-109618 / CVE-2026-109619). Basically I wanted a quick way to
check whether a server is running a patched PHP version or not, without
having to touch exploit code or anything risky - just reading what the
server already tells you.

How it works:
It sends normal GET requests, same as a browser would. No payloads, no
exploit attempts, nothing like that. It just reads the response headers
(X-Powered-By, Server mostly) on a few standard paths - not just the
homepage, since I found out the hard way that some caching/security
setups strip that header only from "/" and leave it on other pages.

For WordPress sites I also try to figure out the WP version itself
(different thing from PHP version, worth knowing too). More on that
below in detect_wordpress_version() - there's a bit of a story behind
how that ended up working the way it does.

A lot of servers hide this stuff on purpose, which is good security
practice honestly. So don't be surprised if you get "unknown" a lot -
that's the tool being honest, not broken. If you need a real answer,
check the server directly (php -v, hosting panel, whatever).

Usage:
    python3 scanner.py targets.txt
    python3 scanner.py                 (no file? it'll just ask you)

targets.txt = one target per line, domain/IP/URL, whatever. # comments
are skipped. No scheme? defaults to https.
"""

import argparse
import csv
import os
import re
import sys
from datetime import datetime, timezone

import requests

# patched releases, per the advisory from Oct 21 2026
# if the patch number is >= this, it's fixed
PATCHED_VERSIONS = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}

VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
REQUEST_TIMEOUT = 8

# not just checking "/" - some setups only strip the version header from
# the homepage and forget about these other standard paths
PROBE_PATHS = ["/", "/wp-login.php", "/xmlrpc.php", "/wp-cron.php"]

# wordpress puts its version in these spots by default
WP_GENERATOR_RE = re.compile(r'generator"[^>]*content="WordPress ([\d.]+)"', re.IGNORECASE)
WP_FEED_GENERATOR_RE = re.compile(r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>", re.IGNORECASE)

# ok so this part took some trial and error to get right. WordPress tags
# its own core CSS/JS files with ?ver=<wp_version> as a cache buster. BUT
# it also bundles a bunch of third-party libraries in the same folders
# (underscore.js, clipboard.js, zxcvbn) and THOSE have their own version
# numbers that have nothing to do with the WP version. First attempt at
# this I grabbed any ?ver= under wp-includes/wp-admin and it picked up
# garbage like "2.0.11" from clipboard.js, totally wrong.
#
# so now it only trusts a specific whitelist of filenames that are known
# to carry $wp_version specifically. and on top of that, some of these
# files get their version scrambled on purpose by caching/security
# plugins (ran into this with hooks.min.js - version string was some
# random hash, not an actual version number). so even within the
# whitelist, I require at least 2 files to agree with each other before
# trusting the result. single source = not good enough.
WP_CORE_VERSIONED_FILES = {
    "wp-util.min.js",
    "wp-util.js",
    "user-profile.min.js",
    "user-profile.js",
    "wp-tooltip.js",
    "wp-tooltip.min.js",
    "password-strength-meter.min.js",
    "password-strength-meter.js",
    "common.min.js",
    "common.js",
    "dashicons.min.css",
    "buttons-rtl.min.css",
    "buttons.min.css",
    "forms-rtl.min.css",
    "forms.min.css",
    "l10n-rtl.min.css",
    "l10n.min.css",
}
WP_CORE_ASSET_RE = re.compile(
    r"/wp-(?:includes|admin)/(?:css|js)/(?:[\w./-]+/)?([\w.-]+?\.(?:js|css))\?ver=([\d]+\.[\d]+(?:\.[\d]+)?)",
    re.IGNORECASE,
)


def normalize_target(raw: str) -> str:
    """adds https:// if nothing's there"""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return ""
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw


def extract_php_version(headers: dict) -> str | None:
    """pulls a PHP version out of the usual headers, if it's there"""
    for header_name in ("X-Powered-By", "Server"):
        value = headers.get(header_name, "")
        match = VERSION_RE.search(value)
        if match:
            return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"
    return None


def classify_version(version_str: str) -> str:
    """patched / vulnerable / unknown-branch, based on PATCHED_VERSIONS above"""
    try:
        major, minor, patch = (int(p) for p in version_str.split("."))
    except ValueError:
        return "unknown-branch"

    branch = (major, minor)
    if branch not in PATCHED_VERSIONS:
        # anything below 8.2 is EOL anyway and never got a patch for this,
        # so treat it as vulnerable no matter what the patch number says
        if (major, minor) < (8, 2):
            return "vulnerable"
        return "unknown-branch"

    patched_major, patched_minor, patched_patch = PATCHED_VERSIONS[branch]
    return "patched" if patch >= patched_patch else "vulnerable"


def detect_wordpress_version(base_url: str, session: requests.Session) -> str:
    """
    Tries to figure out the WordPress version (not PHP - separate thing).
    Checks a few different public sources and only commits to an answer
    if at least two of them agree. Learned that the hard way too -
    originally I just trusted readme.html and it blew up on me (matched
    "PHP version 7.4 or greater" from the system requirements section and
    reported it as the WP version, which was obviously nonsense once I
    actually looked at what it found).

    So now: feed + generator meta tag + the whitelisted core assets
    above, and I only return something if two sources (or two agreeing
    core files) back each other up. Otherwise it returns "" rather than
    guess.
    """
    headers = {"User-Agent": "php2version-scanner/1.0 (+non-intrusive scanner)"}
    candidates = []

    # rss feed generator tag
    try:
        resp = session.get(base_url.rstrip("/") + "/feed/", timeout=REQUEST_TIMEOUT, headers=headers)
        if resp.status_code == 200:
            match = WP_FEED_GENERATOR_RE.search(resp.text)
            if match:
                candidates.append(match.group(1))
    except requests.RequestException:
        pass

    # meta generator tag (some themes still output this)
    try:
        resp = session.get(base_url, timeout=REQUEST_TIMEOUT, headers=headers)
        page_html = resp.text
        match = WP_GENERATOR_RE.search(page_html)
        if match:
            candidates.append(match.group(1))
    except requests.RequestException:
        page_html = ""

    # core asset ?ver= - only counts if 2+ whitelisted files agree, see
    # the big comment up top for why. this is basically what I confirmed
    # manually with Burp Suite before automating it: 4 separate core CSS
    # files all reporting the same version was good enough evidence.
    raw_matches = WP_CORE_ASSET_RE.findall(page_html) if page_html else []
    trusted_versions = [
        version for filename, version in raw_matches if filename.lower() in WP_CORE_VERSIONED_FILES
    ]
    if len(trusted_versions) >= 2 and len(set(trusted_versions)) == 1:
        candidates.extend([trusted_versions[0], trusted_versions[0]])
    elif len(trusted_versions) == 1:
        candidates.append(trusted_versions[0])
    # if they disagree with each other, something's scrambled - don't trust any of it

    if not candidates:
        return ""

    from collections import Counter

    counts = Counter(candidates)
    best_version, best_count = counts.most_common(1)[0]
    return best_version if best_count >= 2 else ""


def check_target(url: str) -> dict:
    """
    Hits a few standard paths on the target looking for a PHP version
    header, then checks for a WP version too if nothing turned up.
    Works fine with plain domains, full URLs, or raw IPs - useful if
    you're pointing this at stuff on your own internal network instead
    of a public site.

    One thing worth mentioning: if HTTPS gets refused outright (TLS
    handshake fails, connection refused, etc), it'll automatically retry
    once over plain HTTP. A lot of internal devices and old admin panels
    never had TLS set up in the first place, so without this the tool
    would just report "error" on stuff that's actually reachable fine.
    """
    result = {
        "target": url,
        "detected_version": "",
        "status": "unknown",
        "wordpress_version": "",
        "http_status": "",
        "error": "",
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    session = requests.Session()
    headers = {"User-Agent": "php2version-scanner/1.0 (+non-intrusive scanner)"}
    last_error = ""
    first_http_status = ""
    http_fallback_tried = False

    for path in PROBE_PATHS:
        probe_url = url.rstrip("/") + path if path != "/" else url
        try:
            response = session.get(probe_url, timeout=REQUEST_TIMEOUT, headers=headers, allow_redirects=True)
            if not first_http_status:
                first_http_status = str(response.status_code)
            version = extract_php_version(response.headers)
            if version:
                result["detected_version"] = version
                result["status"] = classify_version(version)
                result["http_status"] = first_http_status
                result["target"] = url
                break
        except (requests.exceptions.ConnectionError, requests.exceptions.SSLError) as exc:
            # https totally failed - give plain http a shot before giving up
            last_error = str(exc)
            if not http_fallback_tried and url.lower().startswith("https://"):
                http_fallback_tried = True
                url = "http://" + url[len("https://") :]
                probe_url = url.rstrip("/") + path if path != "/" else url
                try:
                    response = session.get(
                        probe_url, timeout=REQUEST_TIMEOUT, headers=headers, allow_redirects=True
                    )
                    if not first_http_status:
                        first_http_status = str(response.status_code)
                    version = extract_php_version(response.headers)
                    if version:
                        result["detected_version"] = version
                        result["status"] = classify_version(version)
                        result["http_status"] = first_http_status
                        result["target"] = url
                        break
                except requests.RequestException as exc2:
                    last_error = str(exc2)
                    continue
            continue
        except requests.RequestException as exc:
            last_error = str(exc)
            continue

    if not result["detected_version"]:
        result["status"] = "unknown (no version header)"
        result["http_status"] = first_http_status
        result["error"] = "" if first_http_status else last_error
        result["target"] = url  # might've switched to http:// above, keep it accurate
        if first_http_status:
            result["wordpress_version"] = detect_wordpress_version(url, session)

    return result


def load_targets(path: str) -> list:
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            normalized = normalize_target(line)
            if normalized:
                targets.append(normalized)
    return targets


def prompt_and_write_targets(path: str) -> str:
    """
    Didn't want people to have to open nano/vim just to list a few
    targets, so if you run this without a file it just asks you
    directly and saves what you type into targets.txt for next time -
    same format as if you'd written it by hand.
    """
    if os.path.exists(path):
        answer = input(f"'{path}' already exists. Overwrite it with new entries? [y/N] ").strip().lower()
        if answer != "y":
            print("Keeping the existing file - using it as-is.")
            return path

    print("\nEnter the domains, IP addresses, or URLs to check, one at a time.")
    print("(Internal/LAN IPs work too - e.g. 192.168.1.10 or 10.0.0.5)")
    print("When you're done, just press Enter on an empty line to start scanning.\n")
    lines = []
    while True:
        try:
            line = input(f"  target #{len(lines) + 1} (Enter to finish): ")
        except EOFError:
            break
        if not line.strip():
            if not lines:
                continue
            break
        lines.append(line.strip())

    if not lines:
        print("No targets entered.", file=sys.stderr)
        sys.exit(1)

    with open(path, "w", encoding="utf-8") as f:
        f.write("# One target per line. Lines starting with # are ignored.\n")
        f.write("# If no scheme is given, https:// is assumed.\n")
        for line in lines:
            f.write(line + "\n")

    print(f"\nSaved {len(lines)} target(s) to {path}\n")
    return path


BANNER = r"""
    ____  __  ______     _____ _________    _   ___   ____________
   / __ \/ / / / __ \   / ___// ____/   |  / | / / | / / ____/ __ \
  / /_/ / /_/ / /_/ /   \__ \/ /   / /| | /  |/ /  |/ / __/ / /_/ /
 / ____/ __  / ____/   ___/ / /___/ ___ |/ /|  / /|  / /___/ _, _/
/_/   /_/ /_/_/       /____/\____/_/  |_/_/ |_/_/ |_/_____/_/ |_|

        Checks if your PHP version is patched against
     CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")  |  v1.0
------------------------------------------------------------
"""


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Non-intrusive PHP2Shell (CVE-2026-109618/109619) patch-status checker."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="One or more domains/IPs/URLs (e.g. example.com 10.0.0.5), "
        "or a single path to a text file with one target per line. "
        "If omitted, you'll be asked to type targets in, and they'll be "
        "saved to targets.txt for next time.",
    )
    parser.add_argument(
        "-o", "--output", default="results.csv", help="Output CSV file (default: results.csv)"
    )
    args = parser.parse_args()

    if not args.targets:
        # nothing given: ask interactively
        targets = load_targets(prompt_and_write_targets("targets.txt"))
    elif len(args.targets) == 1 and os.path.isfile(args.targets[0]):
        # a single existing file: one target per line
        targets = load_targets(args.targets[0])
    elif len(args.targets) == 1 and args.targets[0].lower().endswith((".txt", ".lst", ".list")):
        # looks like a file name but doesn't exist - probably a typo
        print(f"Error: file not found: {args.targets[0]}", file=sys.stderr)
        sys.exit(1)
    else:
        # one or more targets given directly on the command line
        targets = [t for t in (normalize_target(a) for a in args.targets) if t]

    if not targets:
        print("Error: no valid targets found.", file=sys.stderr)
        sys.exit(1)

    print(f"Checking {len(targets)} target(s)...\n")

    rows = []
    for target in targets:
        row = check_target(target)
        rows.append(row)
        wp_note = f" [WordPress {row['wordpress_version']}]" if row["wordpress_version"] else ""
        print(
            f"  {row['target']:<40} -> {row['status']:<25} "
            f"({row['detected_version'] or 'n/a'}){wp_note}"
        )

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "target",
                "detected_version",
                "status",
                "wordpress_version",
                "http_status",
                "error",
                "checked_at",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    vulnerable_count = sum(1 for r in rows if r["status"] == "vulnerable")
    print(f"\nDone. {vulnerable_count} likely-vulnerable target(s) found.")
    print(f"Full results written to: {args.output}")


if __name__ == "__main__":
    main()
