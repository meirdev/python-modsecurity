# python-modsecurity

Python bindings for [libmodsecurity](https://github.com/owasp-modsecurity/ModSecurity).

## Install

```sh
pip install libmodsecurity
```

## Usage

```python
import libmodsecurity

engine = libmodsecurity.ModSecurity()
engine.set_connector_information("my-app/1.0")

rules = libmodsecurity.RulesSet()
rules.load(
    'SecRuleEngine On\n'
    'SecRule REQUEST_URI "@contains /admin" '
    '"id:1,phase:1,deny,status:403,log,msg:\'blocked\'"\n'
)

with engine.transaction(rules) as t:
    t.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
    t.process_uri("/admin", "GET", "1.1")
    t.add_request_header("Host", "example.com")
    t.process_request_headers()

    if it := t.intervention():
        print(f"blocked with {it.status}: {it.log}")
```
