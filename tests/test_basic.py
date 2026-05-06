import pytest

import libmodsecurity


def test_modsecurity_construct():
    m = libmodsecurity.ModSecurity()
    m.set_connector_information("python-modsecurity-tests/0.1")
    assert "ModSecurity" in m.who_am_i()


def test_inline_rule_blocks_request():
    m = libmodsecurity.ModSecurity()
    rules = libmodsecurity.RulesSet()
    loaded = rules.load(
        'SecRuleEngine On\n'
        'SecRule REQUEST_URI "@contains /admin" '
        '"id:1,phase:1,deny,status:403,log,msg:\'admin blocked\'"\n'
    )
    assert loaded >= 0, rules.get_parser_error()

    t = libmodsecurity.Transaction(m, rules)
    t.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
    t.process_uri("/admin", "GET", "1.1")
    t.add_request_header("Host", "example.com")
    t.process_request_headers()

    it = t.intervention()
    assert it is not None
    assert it.status == 403
    assert it.disruptive is True


_WARN_RULE = (
    'SecRuleEngine On\n'
    'SecRule REQUEST_URI "@contains /admin" '
    '"id:1,phase:1,pass,log,msg:\'admin touched\'"\n'
)


def _drive(t: libmodsecurity.Transaction) -> None:
    t.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
    t.process_uri("/admin", "GET", "1.1")
    t.add_request_header("Host", "example.com")
    t.process_request_headers()


def test_log_callback_receives_rule_match():
    m = libmodsecurity.ModSecurity()
    rules = libmodsecurity.RulesSet()
    rules.load(_WARN_RULE)

    messages: list[str] = []
    m.set_log_callback(messages.append)

    _drive(libmodsecurity.Transaction(m, rules))

    m.set_log_callback(None)

    assert any("admin touched" in msg for msg in messages), messages


def test_rule_message_callback_delivers_structured_match():
    m = libmodsecurity.ModSecurity()
    rules = libmodsecurity.RulesSet()
    rules.load(
        'SecRuleEngine On\n'
        'SecRule REQUEST_URI "@contains /admin" '
        '"id:9001,phase:1,pass,log,severity:3,'
        'msg:\'admin touched\',logdata:\'extra\','
        'tag:\'attack\',tag:\'recon\',rev:\'1\',ver:\'OWASP_CRS/4.0\'"\n'
    )

    received: list[libmodsecurity.RuleMessage] = []
    m.set_rule_message_callback(received.append)

    _drive(libmodsecurity.Transaction(m, rules))

    m.set_rule_message_callback(None)

    assert len(received) == 1
    rm = received[0]
    assert rm.rule_id == 9001
    assert rm.phase == 1
    assert rm.severity == 3
    assert rm.message == "admin touched"
    assert rm.data == "extra"
    assert rm.tags == ["attack", "recon"]
    assert rm.rev == "1"
    assert rm.ver == "OWASP_CRS/4.0"
    assert rm.disruptive is False
    assert "/admin" in rm.match


def test_log_callback_unregister_silences():
    m = libmodsecurity.ModSecurity()
    rules = libmodsecurity.RulesSet()
    rules.load(_WARN_RULE)

    messages: list[str] = []
    m.set_log_callback(messages.append)
    m.set_log_callback(None)

    _drive(libmodsecurity.Transaction(m, rules))

    assert messages == []


def test_get_rule_messages_collects_all_matches():
    m = libmodsecurity.ModSecurity()
    rules = libmodsecurity.RulesSet()
    rules.load(
        'SecRuleEngine On\n'
        'SecRule REQUEST_URI "@contains /admin" '
        '"id:1,phase:1,pass,log,severity:3,msg:\'admin touched\'"\n'
        'SecRule REQUEST_HEADERS:User-Agent "@contains scanner" '
        '"id:2,phase:1,pass,log,severity:5,msg:\'scanner ua\'"\n'
    )

    t = libmodsecurity.Transaction(m, rules)
    t.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
    t.process_uri("/admin", "GET", "1.1")
    t.add_request_header("Host", "example.com")
    t.add_request_header("User-Agent", "evil-scanner/1.0")
    t.process_request_headers()
    t.process_logging()

    msgs = t.get_rule_messages()
    ids = sorted(rm.rule_id for rm in msgs)
    assert ids == [1, 2], msgs
    by_id = {rm.rule_id: rm for rm in msgs}
    assert by_id[1].message == "admin touched"
    assert by_id[2].message == "scanner ua"
    assert by_id[2].severity == 5


def test_engine_transaction_context_manager_runs_logging():
    m = libmodsecurity.ModSecurity()
    rules = libmodsecurity.RulesSet()
    rules.load(_WARN_RULE)

    with m.transaction(rules) as t:
        t.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
        t.process_uri("/admin", "GET", "1.1")
        t.add_request_header("Host", "example.com")
        t.process_request_headers()
        msgs_during = t.get_rule_messages()

    # process_logging was invoked on exit; rules messages are still readable
    msgs_after = t.get_rule_messages()
    assert len(msgs_during) == 1
    assert len(msgs_after) == 1


def test_engine_transaction_finalizes_on_exception():
    m = libmodsecurity.ModSecurity()
    rules = libmodsecurity.RulesSet()
    rules.load(_WARN_RULE)

    captured: list[str] = []
    m.set_log_callback(captured.append)

    with pytest.raises(RuntimeError, match="boom"):
        with m.transaction(rules) as t:
            t.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
            t.process_uri("/admin", "GET", "1.1")
            t.add_request_header("Host", "example.com")
            t.process_request_headers()
            raise RuntimeError("boom")

    m.set_log_callback(None)

    # The rule still fired and was captured before the exception
    assert any("admin touched" in line for line in captured)


def test_repr_includes_identifying_fields():
    m = libmodsecurity.ModSecurity()
    assert "ModSecurity v" in repr(m)

    rules = libmodsecurity.RulesSet()
    rules.load(_WARN_RULE)
    captured: list[libmodsecurity.RuleMessage] = []
    m.set_rule_message_callback(captured.append)
    _drive(libmodsecurity.Transaction(m, rules))
    m.set_rule_message_callback(None)

    rm_repr = repr(captured[0])
    assert "rule_id=1" in rm_repr
    assert "'admin touched'" in rm_repr  # Python-style quoting


def test_clean_request_passes():
    m = libmodsecurity.ModSecurity()
    rules = libmodsecurity.RulesSet()
    rules.load(
        'SecRuleEngine On\n'
        'SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"\n'
    )

    t = libmodsecurity.Transaction(m, rules)
    t.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
    t.process_uri("/index.html", "GET", "1.1")
    t.add_request_header("Host", "example.com")
    t.process_request_headers()

    assert t.intervention() is None
