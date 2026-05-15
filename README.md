# endpoint-watch

Watches a target's JavaScript assets and tells you when **new endpoints** or **new secrets** appear in them.

Useful for bug bounty hunters who want a small tool that runs on a cron and pings them on Telegram/Slack/Discord when a target ships new code.

```
$ endpoint-watch https://example.com
[+] https://example.com: found 7 JS file(s)
    [changed] https://example.com/static/app.abc123.js
        + endpoint: /api/v2/users/export
        + endpoint: /internal/debug/whoami
        ! secret (Google API Key): AIzaSyB…
```

## Install

```bash
git clone https://github.com/brennoRD/endpoint-watch
cd endpoint-watch
pip install -r requirements.txt
```

## Usage

```bash
python endpoint_watch.py https://target.tld
python endpoint_watch.py https://target.tld --webhook https://hooks.example/abc
python endpoint_watch.py https://target.tld --json --quiet
```

Snapshots are stored in `~/.endpoint-watch/snapshots.db` (SQLite). First run for a target just records the baseline — second run onward reports diffs.

### Run on a cron

```cron
*/30 * * * * /usr/bin/python3 /opt/endpoint-watch/endpoint_watch.py https://target.tld --webhook https://hooks.example/abc
```

## What it detects

- **New endpoints** — strings that look like paths (`/api/...`) or full URLs (`https://...`) that didn't exist in the previous snapshot of the same JS file.
- **New secrets** — best-effort regex matches for common token formats:
  - AWS Access Key (`AKIA…`)
  - Google API Key (`AIza…`)
  - GitHub Token (`ghp_…`)
  - OpenAI-style key (`sk-…`)
  - Slack Token (`xox[baprs]-…`)
  - JWT (`eyJ…`)

False positives happen — treat output as leads, not findings.

## What it does NOT do

This is intentionally a small tool. It does **not** do auto-probing of new endpoints, risk scoring, deduplication, multi-source correlation, or noise filtering. If you want those, build them on top of the JSON output, or wire it into a larger pipeline.

## License

MIT.
