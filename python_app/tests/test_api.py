from app.main import (
    app,
    get_rules,
    add_app_rule,
    remove_app_rule,
    add_domain_rule,
    remove_domain_rule,
    add_ip_rule,
    remove_ip_rule,
    add_port_rule,
    remove_port_rule,
    get_stats,
    AppRuleRequest,
    DomainRuleRequest,
    IpRuleRequest,
    PortRuleRequest
)


def test_api_rule_crud():
    # 1. Add app rule
    res = add_app_rule(AppRuleRequest(app="NETFLIX"))
    assert "blocked NETFLIX" in res["status"]
    rules = get_rules()
    assert "NETFLIX" in rules["blocked_apps"]

    # 2. Remove app rule
    res = remove_app_rule(app="NETFLIX")
    assert "unblocked NETFLIX" in res["status"]
    rules = get_rules()
    assert "NETFLIX" not in rules["blocked_apps"]

    # 3. Add domain rule
    add_domain_rule(DomainRuleRequest(domain="*.malicious.com"))
    rules = get_rules()
    assert "*.malicious.com" in rules["blocked_domains"]
    remove_domain_rule(domain="*.malicious.com")

    # 4. Add IP rule
    add_ip_rule(IpRuleRequest(ip="10.10.10.10"))
    rules = get_rules()
    assert "10.10.10.10" in rules["blocked_ips"]
    remove_ip_rule(ip="10.10.10.10")

    # 5. Add port rule
    add_port_rule(PortRuleRequest(port=9999))
    rules = get_rules()
    assert 9999 in rules["blocked_ports"]
    remove_port_rule(port=9999)
