# adchecker

BloodHound CE security report generator. Queries the BloodHound Community Edition API to enumerate common Active Directory misconfigurations and produces a single self-contained HTML report per domain.

## Checks

| Check | What it finds |
|---|---|
| **Outbound Object Control** | Objects controlled by Everyone, Authenticated Users, Domain Users, and Domain Computers — with the specific permission edge and target type |
| **Kerberoastable Users** | Enabled users with an SPN set (vulnerable to offline cracking) |
| **AS-REP Roastable Users** | Enabled users that don't require Kerberos pre-authentication |
| **Large Groups with Admin Rights** | Groups exceeding a membership threshold that hold local admin on computers |

## Quick Start

```bash
# 1. Clone / copy this directory
cd adchecker

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env with your BloodHound CE URL, API token ID and key, and domain(s)

# 4. Run
python main.py
```

Reports are written to `./reports/` (configurable via `BH_REPORT_DIR`).

## Configuration

All configuration lives in `.env` — no CLI flags, making it straightforward to cron.

| Variable | Required | Description |
|---|---|---|
| `BH_BASE_URL` | Yes | BloodHound CE instance URL (no trailing slash) |
| `BH_TOKEN_ID` | Yes | API token ID (public part) |
| `BH_TOKEN_KEY` | Yes | API token key (secret part) |
| `BH_DOMAINS` | Yes | Comma-separated domain FQDNs as they appear in BloodHound |
| `BH_REPORT_DIR` | No | Output directory for reports (default: `./reports`) |
| `BH_LARGE_GROUP_THRESHOLD` | No | Minimum group membership to flag in the large-group check (default: `300`) |

### Generating an API Token

1. Log into your BloodHound CE instance
2. Click the gear icon (top right) or go to **My Profile > API Key Management**
3. Click **Create Token**, give it a name, and save
4. Copy the **Token ID** and **Token Key** into your `.env`

The Token Key is only shown once. If lost, revoke and regenerate.

## Cron Example

```cron
# Run daily at 6 AM, reports land in /opt/adchecker/reports/
0 6 * * * cd /opt/adchecker && /usr/bin/python3 main.py >> /var/log/adchecker.log 2>&1
```

## Adding a New Check

1. Create a new file in `checks/` (e.g. `checks/my_new_check.py`)
2. Subclass `BaseCheck` and decorate with `@register`:

```python
from checks import BaseCheck, CheckResult, register
from bhapi.client import BHSession

@register
class MyNewCheck(BaseCheck):
    check_id = "my_new_check"
    title = "My New Check"
    description = "What this check looks for."

    def run(self, session: BHSession, domain: str, **kwargs) -> CheckResult:
        # Use session.cypher() or session.get() to query BloodHound
        rows = [["col1_val", "col2_val"]]
        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            description=self.description,
            headers=["Column 1", "Column 2"],
            rows=rows,
            severity="medium",
        )
```

3. Import it in `checks/__init__.py` at the bottom with the other check imports
4. Run `python main.py` — it will appear in the report automatically

## Project Structure

```
adchecker/
├── main.py              # Entrypoint / orchestrator
├── config.py            # .env loader, all settings
├── .env.example         # Template configuration
├── requirements.txt     # Python dependencies
├── bhapi/
│   ├── __init__.py
│   └── client.py        # HMAC-authenticated API client
├── checks/
│   ├── __init__.py      # Check base class, registry, auto-imports
│   ├── outbound_control.py
│   ├── kerberoastable.py
│   ├── asrep_roastable.py
│   └── large_group_admin.py
├── report/
│   ├── __init__.py
│   └── renderer.py      # Self-contained HTML report generator
└── reports/             # Generated reports (git-ignored)
```

## Dependencies

- Python 3.9+
- `requests` — HTTP client
- `python-dotenv` — .env file loading
- `jinja2` — reserved for future template expansion

## Authentication

Uses HMAC signed requests as recommended by SpecterOps. Each request is signed with:
- The HTTP method + URI (prevents method/path tampering)
- A timestamp truncated to the hour (prevents replay beyond 2h)
- The request body (prevents payload modification)

This is more secure than JWT bearer tokens and the keys don't expire.
