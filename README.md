# python-modsecurity

Python bindings for [libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity).

## Install

```sh
pip install libmodsecurity
```

with `uv`:

```sh
uv venv --python 3.13
uv add libmodsecurity
```

## Usage

```python
from libmodsecurity import ModSecurity, RulesSet

engine = ModSecurity()
engine.set_connector_information("my-app/1.0")

rules = RulesSet()
rules.load("""
SecRuleEngine On
SecRule REQUEST_URI "@contains /admin" \
    "id:1,phase:1,deny,status:403,log,msg:'blocked'"
""")

with engine.transaction(rules) as t:
    t.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
    t.process_uri("/admin", "GET", "1.1")
    t.add_request_header("Host", "example.com")
    t.process_request_headers()

    if it := t.intervention():
        print(f"blocked with {it.status}: {it.log}")
```

## ASGI middleware

The package ships a ready-to-use ASGI middleware at `libmodsecurity.asgi`. Point
it at your application via `WAF_APP` (`module:attr`) and a SecRules config via
`WAF_RULES`:

```sh
WAF_APP=app:app WAF_RULES=./config/init.conf \
uv run gunicorn -k gunicorn.workers.gasgi.ASGIWorker libmodsecurity.asgi:app
```
