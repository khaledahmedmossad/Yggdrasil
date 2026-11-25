# Development

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Tests

```bash
pytest
```

## Design notes

- LDAP operations are isolated in `integrations/ldap_client.py`.
- Enumeration is read-only and uses the AD matching rule in `modules/enumeration.py`.
- Assessment rules are deterministic and do not claim exploitability.
- Output renderers should not receive or store bind credentials.
