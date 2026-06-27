#!/usr/bin/env python3
"""
test_rest_api.py -- REST API validation tests
Run from any terminal that can reach the controller (localhost:8080).
Does NOT require Mininet -- tests only the HTTP interface.

Usage:
    python3 tests/test_rest_api.py
"""

import json
import sys
import urllib.request
import urllib.error

BASE = 'http://localhost:8080'
passed = 0
failed = 0


def req(method, path, body=None):
    """Send an HTTP request and return (status_code, parsed_json_or_None)."""
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    headers = {'Content-Type': 'application/json'} if body else {}
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, None


def check(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  PASS  {name}')
    else:
        failed += 1
        print(f'  FAIL  {name}  -- {detail}')


def test_ip_blocking():
    print('\n-- IP Blocking --')

    code, data = req('POST', '/firewall/rules/ip/10.0.0.3')
    check('Add valid IP returns 200', code == 200)
    check('Response contains blocked IP', '10.0.0.3' in data.get('blocked_ips', []))

    code, data = req('POST', '/firewall/rules/ip/10.0.0.3')
    check('Duplicate add returns 200', code == 200)
    check('Set contains IP only once', data.get('blocked_ips', []).count('10.0.0.3') == 1)

    code, data = req('POST', '/firewall/rules/ip/not_an_ip')
    check('Invalid IP returns 400', code == 400)
    check('Error message mentions invalid', 'Invalid' in data.get('msg', ''))

    code, data = req('POST', '/firewall/rules/ip/999.0.0.1')
    check('Overflow octet returns 400', code == 400)

    code, data = req('DELETE', '/firewall/rules/ip/10.0.0.3')
    check('Delete existing IP returns 200', code == 200)
    check('IP removed from list', '10.0.0.3' not in data.get('blocked_ips', []))

    code, data = req('DELETE', '/firewall/rules/ip/10.0.0.99')
    check('Delete non-existent IP returns 404', code == 404)

    code, data = req('DELETE', '/firewall/rules/ip/garbage')
    check('Delete invalid IP returns 400', code == 400)


def test_port_blocking():
    print('\n-- Port Blocking --')

    code, data = req('POST', '/firewall/rules/port/80/6')
    check('Add TCP port 80 returns 200', code == 200)

    code, data = req('POST', '/firewall/rules/port/5000/17')
    check('Add UDP port 5000 returns 200', code == 200)

    code, data = req('POST', '/firewall/rules/port/99999/6')
    check('Port 99999 returns 400', code == 400)
    check('Error mentions range', 'range' in data.get('msg', '').lower())

    code, data = req('POST', '/firewall/rules/port/-1/6')
    check('Negative port returns 400', code == 400)

    code, data = req('POST', '/firewall/rules/port/80/99')
    check('Proto 99 returns 400', code == 400)
    check('Error mentions proto', 'Proto' in data.get('msg', '') or 'proto' in data.get('msg', ''))

    req('DELETE', '/firewall/rules/port/80/6')
    req('DELETE', '/firewall/rules/port/5000/17')

    code, _ = req('DELETE', '/firewall/rules/port/80/6')
    check('Delete port returns 200 (even if already removed)', code == 200)


def test_rate_limit():
    print('\n-- Rate Limiting --')

    code, data = req('POST', '/firewall/rules/ratelimit', {'limit': 50, 'window': 5})
    check('Set rate limit returns 200', code == 200)

    code, data = req('GET', '/firewall/rules')
    check('Rate limit updated', data.get('rate_limit') == 50 and data.get('rate_window') == 5)

    req('POST', '/firewall/rules/ratelimit', {'limit': 1000, 'window': 1})


def test_dpi_patterns():
    print('\n-- DPI Patterns --')

    code, data = req('GET', '/firewall/dpi')
    check('GET /dpi returns 200', code == 200)
    check('Has 6 built-in patterns', isinstance(data, list) and len([p for p in data if p.get('builtin')]) == 6)

    code, data = req('POST', '/firewall/dpi', {
        'name': 'TEST_PATTERN', 'pattern': 'test_[a-z]+', 'description': 'test'
    })
    check('Add user pattern returns 200', code == 200)
    check('Response has pattern name', data.get('pattern') == 'TEST_PATTERN')

    code, data = req('POST', '/firewall/dpi', {
        'name': 'TEST_PATTERN', 'pattern': 'xyz', 'description': ''
    })
    check('Duplicate name returns 400', code == 400)
    check('Error mentions exists', 'exists' in data.get('msg', ''))

    code, data = req('POST', '/firewall/dpi', {
        'name': 'EMPTY', 'pattern': '', 'description': ''
    })
    check('Empty pattern returns 400', code == 400)

    code, data = req('POST', '/firewall/dpi', {
        'name': '', 'pattern': 'abc', 'description': ''
    })
    check('Empty name returns 400', code == 400)

    code, data = req('POST', '/firewall/dpi', {
        'name': 'BAD_REGEX', 'pattern': '(a+)+', 'description': 'backtrack bomb'
    })
    check('Dangerous regex returns 400', code == 400)
    check('Error mentions backtracking', 'backtrack' in data.get('msg', '').lower())

    code, data = req('POST', '/firewall/dpi', {
        'name': 'BAD_SYNTAX', 'pattern': '[unclosed', 'description': ''
    })
    check('Invalid regex returns 400', code == 400)

    code, data = req('DELETE', '/firewall/dpi/TEST_PATTERN')
    check('Delete user pattern returns 200', code == 200)

    code, data = req('DELETE', '/firewall/dpi/DOES_NOT_EXIST')
    check('Delete non-existent returns 404', code == 404)

    code, data = req('DELETE', '/firewall/dpi/SQL_INJECTION')
    check('Delete built-in returns 403', code == 403)
    check('Error mentions built-in', 'built-in' in data.get('msg', ''))


def test_stats_and_log():
    print('\n-- Stats & Log --')

    code, data = req('GET', '/firewall/stats')
    check('GET /stats returns 200', code == 200)
    check('Stats has total key', 'total' in data)
    check('Stats has allowed key', 'allowed' in data)
    check('Stats has dpi_blocked key', 'dpi_blocked' in data)

    code, data = req('GET', '/firewall/log')
    check('GET /log returns 200', code == 200)
    check('Log is a list', isinstance(data, list))


def test_rules_endpoint():
    print('\n-- Rules Endpoint --')

    code, data = req('GET', '/firewall/rules')
    check('GET /rules returns 200', code == 200)
    check('Has blocked_ips', 'blocked_ips' in data)
    check('Has blocked_ports', 'blocked_ports' in data)
    check('Has rate_limit', 'rate_limit' in data)
    check('Has rate_window', 'rate_window' in data)


def main():
    try:
        req('GET', '/firewall/stats')
    except Exception:
        print(f'ERROR: Cannot reach controller at {BASE}')
        print('Start the controller first: .venv/bin/python3 src/main.py')
        sys.exit(1)

    test_rules_endpoint()
    test_ip_blocking()
    test_port_blocking()
    test_rate_limit()
    test_dpi_patterns()
    test_stats_and_log()

    print(f'\n{"=" * 40}')
    print(f'  {passed} passed, {failed} failed')
    print(f'{"=" * 40}')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
