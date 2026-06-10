#!/usr/bin/env python3
"""Tests for PIF PreToolUse hook."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hook import _check_bash_web_access, _extract_urls_from_command, _is_trusted


class TestBashWebAccess(unittest.TestCase):
    """Detect web-fetching shell commands."""

    def test_curl_with_url(self):
        self.assertTrue(_check_bash_web_access(
            'curl -sL "https://example.com" -H "User-Agent: Mozilla"'
        ))

    def test_wget_with_url(self):
        self.assertTrue(_check_bash_web_access(
            'wget https://example.com/page -O output.html'
        ))

    def test_python_urllib(self):
        self.assertTrue(_check_bash_web_access(
            'python3 -c "import urllib.request; urllib.request.urlopen(\'https://evil.com\')"'
        ))

    def test_python_requests(self):
        self.assertTrue(_check_bash_web_access(
            'python3 -c "import requests; requests.get(\'https://evil.com\')"'
        ))

    def test_http_command(self):
        self.assertTrue(_check_bash_web_access(
            'http GET https://api.example.com/data'
        ))

    def test_normal_commands_pass(self):
        self.assertFalse(_check_bash_web_access('ls -la /tmp'))
        self.assertFalse(_check_bash_web_access('git status'))
        self.assertFalse(_check_bash_web_access('npm install'))
        self.assertFalse(_check_bash_web_access('python3 -m pytest tests/'))

    def test_curl_without_url_passes(self):
        self.assertFalse(_check_bash_web_access('curl --version'))
        self.assertFalse(_check_bash_web_access('which curl'))

    def test_url_without_fetch_command_passes(self):
        self.assertFalse(_check_bash_web_access(
            'echo "visit https://example.com for more info"'
        ))

    def test_empty_command(self):
        self.assertFalse(_check_bash_web_access(''))
        self.assertFalse(_check_bash_web_access(None))

    def test_grep_with_url_pattern_passes(self):
        self.assertFalse(_check_bash_web_access(
            'grep -r "https://api" src/'
        ))

    def test_git_clone_passes(self):
        self.assertFalse(_check_bash_web_access(
            'git clone https://github.com/user/repo.git'
        ))


class TestLocalhostExemption(unittest.TestCase):
    """Localhost URLs should pass through the hook."""

    def test_curl_localhost(self):
        self.assertFalse(_check_bash_web_access(
            'curl -s http://localhost:8080/health'
        ))

    def test_curl_127(self):
        self.assertFalse(_check_bash_web_access(
            'curl http://127.0.0.1:3000/api/v1'
        ))

    def test_curl_ipv6_loopback(self):
        self.assertFalse(_check_bash_web_access(
            'curl http://[::1]:8080/'
        ))

    def test_curl_external_still_blocked(self):
        self.assertTrue(_check_bash_web_access(
            'curl https://example.com'
        ))

    def test_mixed_localhost_and_external_blocked(self):
        self.assertTrue(_check_bash_web_access(
            'curl http://localhost:8080 && curl https://example.com'
        ))

    def test_localhost_https(self):
        self.assertFalse(_check_bash_web_access(
            'curl https://localhost:3000/health'
        ))

    def test_curl_localhost_shell_variable_port(self):
        self.assertFalse(_check_bash_web_access(
            'for port in 3002 3000; do curl -s "http://localhost:$port/"; done'
        ))

    def test_curl_localhost_braced_variable_port(self):
        self.assertFalse(_check_bash_web_access(
            'curl "http://127.0.0.1:${PORT}/health"'
        ))


class TestExtractUrls(unittest.TestCase):

    def test_single_url(self):
        urls = _extract_urls_from_command('curl https://example.com')
        self.assertEqual(urls, ['https://example.com'])

    def test_multiple_urls(self):
        urls = _extract_urls_from_command(
            'curl https://a.com && curl https://b.com'
        )
        self.assertEqual(len(urls), 2)

    def test_no_urls(self):
        urls = _extract_urls_from_command('ls -la')
        self.assertEqual(urls, [])


class TestTrustedDomains(unittest.TestCase):

    def test_exact_match(self):
        self.assertTrue(_is_trusted('https://example.com/page', ['example.com']))

    def test_subdomain_match(self):
        self.assertTrue(_is_trusted('https://api.example.com/v1', ['example.com']))

    def test_no_match(self):
        self.assertFalse(_is_trusted('https://evil.com', ['example.com']))

    def test_empty_url(self):
        self.assertFalse(_is_trusted('', ['example.com']))
        self.assertFalse(_is_trusted('(no url)', ['example.com']))


if __name__ == '__main__':
    unittest.main()
