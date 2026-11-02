"""Add a Content-Security-Policy tag with hashes of a page's inline script and style."""
import base64
import hashlib
import re
import sys

MARKER = "<!-- Content-Security-Policy is added here at deploy by .github/scripts/add_csp.py -->"


def inline_hashes(page, tag):
    blocks = re.findall(rf"<{tag}\b[^>]*>(.*?)</{tag}>", page, re.DOTALL)
    if not blocks:
        sys.exit(f"No <{tag}> found")
    digests = (hashlib.sha256(block.encode("utf-8")).digest() for block in blocks)
    return " ".join(f"'sha256-{base64.b64encode(digest).decode()}'" for digest in digests)


path = sys.argv[1]
with open(path, encoding="utf-8", newline="") as file:
    page = file.read()

if page.count(MARKER) != 1:
    sys.exit(f"Expected exactly one CSP marker in {path}")

policy = (
    "default-src 'none'; "
    f"script-src {inline_hashes(page, 'script')}; "
    f"style-src {inline_hashes(page, 'style')}; "
    "img-src data:; "
    "base-uri 'none'; "
    "form-action 'none'"
)
tag = f'<meta http-equiv="Content-Security-Policy" content="{policy}">'

with open(path, "w", encoding="utf-8", newline="") as file:
    file.write(page.replace(MARKER, tag))

print(tag)
