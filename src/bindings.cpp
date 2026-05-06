#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/rule.h>
#include <modsecurity/rule_message.h>
#include <modsecurity/rule_with_actions.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace py = pybind11;
namespace ms = modsecurity;

namespace {

struct PyRuleMessage {
    int64_t rule_id;
    int phase;
    int severity;
    int accuracy;
    int maturity;
    int line;
    bool disruptive;
    bool no_audit_log;
    std::string message;
    std::string match;
    std::string data;
    std::string reference;
    std::string rev;
    std::string ver;
    std::string file;
    std::vector<std::string> tags;
};

PyRuleMessage to_py_rule_message(const ms::RuleMessage &rm) {
    PyRuleMessage p;
    p.rule_id = rm.m_rule.m_ruleId;
    p.phase = rm.getPhase();
    p.severity = rm.m_severity;
    p.accuracy = rm.m_rule.m_accuracy;
    p.maturity = rm.m_rule.m_maturity;
    p.line = rm.m_rule.getLineNumber();
    p.disruptive = rm.m_isDisruptive;
    p.no_audit_log = rm.m_noAuditLog;
    p.message = rm.m_message;
    p.match = rm.m_match;
    p.data = rm.m_data;
    p.reference = rm.m_reference;
    p.rev = rm.m_rule.m_rev;
    p.ver = rm.m_rule.m_ver;
    p.file = rm.m_rule.getFileName();
    p.tags.assign(rm.m_tags.begin(), rm.m_tags.end());
    return p;
}

struct LogState {
    py::object callback;
    bool structured = false;
};

std::unordered_map<ms::ModSecurity *, LogState> &log_state_registry() {
    static std::unordered_map<ms::ModSecurity *, LogState> registry;
    return registry;
}

extern "C" void log_trampoline(void *user_data, const void *payload) {
    if (!user_data || !payload) {
        return;
    }
    auto *engine = static_cast<ms::ModSecurity *>(user_data);

    py::gil_scoped_acquire gil;
    auto &registry = log_state_registry();
    auto it = registry.find(engine);
    if (it == registry.end()) {
        return;
    }

    try {
        if (it->second.structured) {
            const auto *rm = static_cast<const ms::RuleMessage *>(payload);
            it->second.callback(to_py_rule_message(*rm));
        } else {
            const char *text = static_cast<const char *>(payload);
            it->second.callback(text);
        }
    } catch (py::error_already_set &e) {
        e.discard_as_unraisable(it->second.callback);
    }
}

void install_callback(ms::ModSecurity &self, py::object callback,
                      bool structured) {
    auto &registry = log_state_registry();
    if (callback.is_none()) {
        registry.erase(&self);
        self.setServerLogCb(nullptr);
        return;
    }
    if (!py::hasattr(callback, "__call__")) {
        throw py::type_error("callback must be callable or None");
    }
    registry[&self] = LogState{std::move(callback), structured};
    self.setServerLogCb(&log_trampoline,
                        structured ? ms::RuleMessageLogProperty
                                   : ms::TextLogProperty);
}

void set_log_callback(ms::ModSecurity &self, py::object callback) {
    install_callback(self, std::move(callback), /*structured=*/false);
}

void set_rule_message_callback(ms::ModSecurity &self, py::object callback) {
    install_callback(self, std::move(callback), /*structured=*/true);
}



struct InterventionResult {
    int status;
    std::optional<std::string> url;
    std::optional<std::string> log;
    bool pause;
    bool disruptive;
};

std::optional<InterventionResult> consume_intervention(ms::Transaction *t) {
    ms::ModSecurityIntervention it;
    it.status = 200;
    it.url = nullptr;
    it.log = nullptr;
    it.disruptive = 0;
    it.pause = 0;

    if (!t->intervention(&it)) {
        return std::nullopt;
    }

    InterventionResult r;
    r.status = it.status;
    r.disruptive = it.disruptive != 0;
    r.pause = it.pause != 0;
    if (it.url) {
        r.url = std::string(it.url);
        std::free(it.url);
    }
    if (it.log) {
        r.log = std::string(it.log);
        std::free(it.log);
    }
    return r;
}

constexpr auto kInterventionDoc =
    "An action requested by ModSecurity (block, redirect, log) following a\n"
    "process_* call. Returned by Transaction.intervention().";

constexpr auto kModSecurityDoc =
    "Top-level ModSecurity engine. One instance is shared across all\n"
    "transactions; pair it with a RulesSet to drive request inspection.";

constexpr auto kSetConnectorInformationDoc =
    "Set information about the connector using the library.\n"
    "\n"
    "Used in audit logs to identify the integration. Recommended pattern:\n"
    "    \"ConnectorName vX.Y.Z-tag (extra)\"\n"
    "for example, \"ModSecurity-nginx v0.0.1-alpha (Whee)\".";

constexpr auto kWhoAmIDoc =
    "Return information about the ModSecurity version and platform.\n"
    "\n"
    "Format is stable so log parsers can rely on it; new fields are only\n"
    "appended to the end of the string.";

constexpr auto kSetLogCallbackDoc =
    "Register a callable to receive ModSecurity server-log messages as\n"
    "formatted text (Apache-style log lines). Pass None to unregister.\n"
    "\n"
    "Exceptions raised by the callback are reported via\n"
    "sys.unraisablehook and do not propagate into rule evaluation.\n"
    "\n"
    "Replaces any previously installed log or rule-message callback on\n"
    "this engine. Unregister with set_log_callback(None) before letting\n"
    "this ModSecurity instance be garbage collected, otherwise the\n"
    "registry entry leaks until process exit.";

constexpr auto kSetRuleMessageCallbackDoc =
    "Register a callable to receive structured RuleMessage objects (rule\n"
    "id, severity, message, match, tags, etc.) instead of formatted text.\n"
    "Pass None to unregister.\n"
    "\n"
    "The RuleMessage passed in is fully copied from libmodsecurity; it is\n"
    "safe to keep references to it past the callback's return.\n"
    "\n"
    "Replaces any previously installed log or rule-message callback on\n"
    "this engine. Same lifetime caveat as set_log_callback().";

constexpr auto kRuleMessageDoc =
    "A structured rule-match record. Populated by libmodsecurity each\n"
    "time a non-disruptive SecRule fires, and delivered to the callback\n"
    "registered via ModSecurity.set_rule_message_callback().";

constexpr auto kRulesSetDoc =
    "A compiled set of SecRules. Load rules with load() or load_from_uri()\n"
    "before passing the RulesSet to a Transaction.";

constexpr auto kLoadFromUriDoc =
    "Load rules from a file path.\n"
    "\n"
    "Returns the number of rules loaded, or -1 on parse failure (call\n"
    "get_parser_error() for details).";

constexpr auto kLoadDoc =
    "Load rules from an in-memory string of SecLanguage directives.\n"
    "\n"
    "Returns the number of rules loaded, or -1 on parse failure (call\n"
    "get_parser_error() for details).";

constexpr auto kGetParserErrorDoc =
    "Return the parser error from the last failed load. Empty if the last\n"
    "load succeeded.";

constexpr auto kTransactionDoc =
    "A single HTTP request/response analysis cycle.\n"
    "\n"
    "Drive a Transaction through the SecRules phases by calling, in order:\n"
    "  process_connection -> process_uri ->\n"
    "  add_request_header* -> process_request_headers ->\n"
    "  append_request_body* -> process_request_body ->\n"
    "  add_response_header* -> process_response_headers ->\n"
    "  append_response_body* -> process_response_body ->\n"
    "  process_logging\n"
    "\n"
    "After each step, call intervention() to see whether the engine wants\n"
    "the connector to block, redirect, or pause the request.";

constexpr auto kProcessConnectionDoc =
    "Run analysis on the connection. Should be the very first call on a\n"
    "transaction, before virtual host resolution.\n"
    "\n"
    "Remember to call intervention() afterwards.";

constexpr auto kProcessURIDoc =
    "Run analysis on the URI and query-string variables.\n"
    "\n"
    "Sits logically between SecLanguage phases 1 and 2. Remember to call\n"
    "intervention() afterwards.";

constexpr auto kAddRequestHeaderDoc =
    "Feed ModSecurity a request header. Add all headers before calling\n"
    "process_request_headers().";

constexpr auto kProcessRequestHeadersDoc =
    "Run analysis on the request headers (SecLanguage phase 1). All\n"
    "request headers must have been added first via add_request_header().\n"
    "\n"
    "Remember to call intervention() afterwards.";

constexpr auto kAppendRequestBodyDoc =
    "Feed ModSecurity request body bytes for inspection. May be called\n"
    "repeatedly to stream the body in chunks.\n"
    "\n"
    "Buffering each chunk is computationally expensive; check\n"
    "intervention() between chunks because rules may set a maximum\n"
    "inspection size.";

constexpr auto kProcessRequestBodyDoc =
    "Run analysis on the request body (SecLanguage phase 2). Optional if\n"
    "there is no body. The body must have been appended first via\n"
    "append_request_body().\n"
    "\n"
    "Remember to call intervention() afterwards.";

constexpr auto kAddResponseHeaderDoc =
    "Feed ModSecurity a response header. Add all headers before calling\n"
    "process_response_headers().";

constexpr auto kProcessResponseHeadersDoc =
    "Run analysis on the response headers (SecLanguage phase 3).\n"
    "\n"
    "Pass the HTTP status code and the protocol string (for example,\n"
    "\"HTTP/1.1\"). All response headers must have been added first.\n"
    "Remember to call intervention() afterwards.";

constexpr auto kAppendResponseBodyDoc =
    "Feed ModSecurity response body bytes for inspection. ModSecurity may\n"
    "also rewrite the body (limited support); if it does, do not send the\n"
    "original Content-Length header to the client.";

constexpr auto kProcessResponseBodyDoc =
    "Run analysis on the response body (SecLanguage phase 4). Optional if\n"
    "there is no body. The body must have been appended first via\n"
    "append_response_body().\n"
    "\n"
    "Remember to call intervention() afterwards.";

constexpr auto kProcessLoggingDoc =
    "Run the logging phase (SecLanguage phase 5). Writes the audit log if\n"
    "the transaction is relevant. The response can already have been\n"
    "delivered to the client when this is called.";

constexpr auto kInterventionMethodDoc =
    "Return an Intervention if ModSecurity wants the connector to act\n"
    "(block, redirect, log), otherwise None. Should be called after each\n"
    "process_* step.";

constexpr auto kGetRuleMessagesDoc =
    "Return all RuleMessage records collected for this transaction.\n"
    "\n"
    "Each entry corresponds to a SecRule that matched during evaluation,\n"
    "covering both disruptive and non-disruptive matches. Useful for\n"
    "shipping audit events to a SIEM after process_logging() has run.";

}  // namespace

PYBIND11_MODULE(_libmodsecurity, m) {
    m.doc() = "Python bindings for libmodsecurity (OWASP ModSecurity v3)";

    py::class_<PyRuleMessage>(m, "RuleMessage", kRuleMessageDoc)
        .def_readonly("rule_id", &PyRuleMessage::rule_id,
                      "Numeric rule id (the SecRule `id:N` action).")
        .def_readonly("phase", &PyRuleMessage::phase,
                      "SecLanguage phase the rule fired in (1 through 5).")
        .def_readonly("severity", &PyRuleMessage::severity,
                      "Rule severity (0=EMERGENCY, 7=DEBUG).")
        .def_readonly("accuracy", &PyRuleMessage::accuracy,
                      "Rule's `accuracy:N` value, or 0 if unset.")
        .def_readonly("maturity", &PyRuleMessage::maturity,
                      "Rule's `maturity:N` value, or 0 if unset.")
        .def_readonly("line", &PyRuleMessage::line,
                      "Line number of the rule in its source file.")
        .def_readonly("disruptive", &PyRuleMessage::disruptive,
                      "True if the rule action is disruptive (deny, drop, "
                      "redirect); False for warn/log/pass matches.")
        .def_readonly("no_audit_log", &PyRuleMessage::no_audit_log,
                      "True if the `noauditlog` action was applied.")
        .def_readonly("message", &PyRuleMessage::message,
                      "Value of the rule's `msg:` action.")
        .def_readonly("match", &PyRuleMessage::match,
                      "The substring or value that matched the rule's "
                      "operator.")
        .def_readonly("data", &PyRuleMessage::data,
                      "Value of the rule's `logdata:` action.")
        .def_readonly("reference", &PyRuleMessage::reference,
                      "Variable references describing where the match "
                      "occurred (e.g. \"o0,4v9,4\").")
        .def_readonly("rev", &PyRuleMessage::rev,
                      "Rule revision string from the `rev:` action.")
        .def_readonly("ver", &PyRuleMessage::ver,
                      "Rule version string from the `ver:` action.")
        .def_readonly("file", &PyRuleMessage::file,
                      "Source file the rule was loaded from, or empty if "
                      "loaded from an in-memory string.")
        .def_readonly("tags", &PyRuleMessage::tags,
                      "List of tags attached to the rule via `tag:`.")
        .def("__repr__", [](const PyRuleMessage &r) {
            return py::str(
                "RuleMessage(rule_id={}, phase={}, severity={}, "
                "disruptive={}, message={!r}, match={!r})")
                .attr("format")(r.rule_id, r.phase, r.severity,
                                r.disruptive, r.message, r.match)
                .cast<std::string>();
        });

    py::class_<InterventionResult>(m, "Intervention", kInterventionDoc)
        .def_readonly("status", &InterventionResult::status,
                      "HTTP status code to return to the client (e.g. 403). "
                      "Defaults to 200 if no rule overrode it.")
        .def_readonly("url", &InterventionResult::url,
                      "Redirect URL to send the client to, or None.")
        .def_readonly("log", &InterventionResult::log,
                      "Human-readable log message describing why the action "
                      "was taken, or None.")
        .def_readonly("pause", &InterventionResult::pause,
                      "Whether the connector should pause processing.")
        .def_readonly("disruptive", &InterventionResult::disruptive,
                      "True for disruptive actions (block, redirect); False "
                      "for log-only events.")
        .def("__repr__", [](const InterventionResult &r) {
            return py::str(
                "Intervention(status={}, disruptive={}, pause={}, "
                "url={!r}, log={!r})")
                .attr("format")(r.status, r.disruptive, r.pause,
                                r.url ? py::cast(*r.url) : py::none(),
                                r.log ? py::cast(*r.log) : py::none())
                .cast<std::string>();
        });

    py::class_<ms::ModSecurity>(m, "ModSecurity", kModSecurityDoc)
        .def(py::init<>())
        .def("set_connector_information",
             [](ms::ModSecurity &self, const std::string &info) {
                 self.setConnectorInformation(info);
             },
             py::arg("info"),
             kSetConnectorInformationDoc)
        .def("who_am_i", &ms::ModSecurity::whoAmI, kWhoAmIDoc)
        .def("set_log_callback", &set_log_callback,
             py::arg("callback"), kSetLogCallbackDoc)
        .def("set_rule_message_callback", &set_rule_message_callback,
             py::arg("callback"), kSetRuleMessageCallbackDoc)
        .def("__repr__", [](ms::ModSecurity &self) {
            return py::str("ModSecurity({!r})")
                .attr("format")(self.whoAmI())
                .cast<std::string>();
        });

    py::class_<ms::RulesSet>(m, "RulesSet", kRulesSetDoc)
        .def(py::init<>())
        .def("load_from_uri",
             [](ms::RulesSet &self, const std::string &uri) {
                 return self.loadFromUri(uri.c_str());
             },
             py::arg("uri"),
             kLoadFromUriDoc)
        .def("load",
             [](ms::RulesSet &self, const std::string &plain_rules) {
                 return self.load(plain_rules.c_str());
             },
             py::arg("plain_rules"),
             kLoadDoc)
        .def("get_parser_error",
             [](const ms::RulesSet &self) { return self.getParserError(); },
             kGetParserErrorDoc);

    py::class_<ms::Transaction>(m, "Transaction", kTransactionDoc)
        .def(py::init([](ms::ModSecurity *modsec, ms::RulesSet *rules) {
                 return std::make_unique<ms::Transaction>(modsec, rules, modsec);
             }),
             py::arg("modsecurity"),
             py::arg("rules"),
             py::keep_alive<1, 2>(),
             py::keep_alive<1, 3>())
        .def("process_connection",
             [](ms::Transaction &t, const std::string &client, int cport,
                const std::string &server, int sport) {
                 return t.processConnection(client.c_str(), cport,
                                            server.c_str(), sport);
             },
             py::arg("client_ip"), py::arg("client_port"),
             py::arg("server_ip"), py::arg("server_port"),
             kProcessConnectionDoc)
        .def("process_uri",
             [](ms::Transaction &t, const std::string &uri,
                const std::string &method, const std::string &http_version) {
                 return t.processURI(uri.c_str(), method.c_str(),
                                     http_version.c_str());
             },
             py::arg("uri"), py::arg("method"), py::arg("http_version"),
             kProcessURIDoc)
        .def("add_request_header",
             [](ms::Transaction &t, const std::string &k, const std::string &v) {
                 return t.addRequestHeader(k, v);
             },
             py::arg("name"), py::arg("value"),
             kAddRequestHeaderDoc)
        .def("process_request_headers", &ms::Transaction::processRequestHeaders,
             kProcessRequestHeadersDoc)
        .def("append_request_body",
             [](ms::Transaction &t, py::bytes body) {
                 std::string s = body;
                 return t.appendRequestBody(
                     reinterpret_cast<const unsigned char *>(s.data()), s.size());
             },
             py::arg("body"),
             kAppendRequestBodyDoc)
        .def("process_request_body", &ms::Transaction::processRequestBody,
             kProcessRequestBodyDoc)
        .def("add_response_header",
             [](ms::Transaction &t, const std::string &k, const std::string &v) {
                 return t.addResponseHeader(k, v);
             },
             py::arg("name"), py::arg("value"),
             kAddResponseHeaderDoc)
        .def("process_response_headers",
             [](ms::Transaction &t, int code, const std::string &proto) {
                 return t.processResponseHeaders(code, proto);
             },
             py::arg("status_code"), py::arg("protocol"),
             kProcessResponseHeadersDoc)
        .def("append_response_body",
             [](ms::Transaction &t, py::bytes body) {
                 std::string s = body;
                 return t.appendResponseBody(
                     reinterpret_cast<const unsigned char *>(s.data()), s.size());
             },
             py::arg("body"),
             kAppendResponseBodyDoc)
        .def("process_response_body", &ms::Transaction::processResponseBody,
             kProcessResponseBodyDoc)
        .def("process_logging", &ms::Transaction::processLogging,
             kProcessLoggingDoc)
        .def("intervention", &consume_intervention, kInterventionMethodDoc)
        .def("get_rule_messages",
             [](const ms::Transaction &t) {
                 std::vector<PyRuleMessage> out;
                 out.reserve(t.m_rulesMessages.size());
                 for (const auto &rm : t.m_rulesMessages) {
                     out.push_back(to_py_rule_message(rm));
                 }
                 return out;
             },
             kGetRuleMessagesDoc);
}
