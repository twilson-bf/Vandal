"""Redaction for timeline displays/exports; original evidence stays access controlled."""
import re


def command(text):
    text = re.sub(r'(https?://)[^\s/@:]+:[^\s/@]+@', r'\1[REDACTED]@', str(text), flags=re.I)
    text = re.sub(r'((?:password|passwd|pass|token|secret|api[_-]?key|authorization)\s*[=:]\s*)([^,\s"\']+)', r'\1[REDACTED]', text, flags=re.I)
    text = re.sub(r'(--?(?:password|passwd|pass|token|secret|api[_-]?key)\s+)("[^"]*"|\'[^\']*\'|\S+)', r'\1[REDACTED]', text, flags=re.I)
    return text
