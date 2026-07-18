from pathlib import Path

path = Path("TODO_AUTHENTICATION_IDEAS.md")
text = path.read_text(encoding="utf-8")
old = """user=A;days=Mo-Fr;time=0800-1400;override=A.secret
user=B;days=Mo-Fr;time=1400-2000;override=B.secret
user=C;days=Mo-Fr;time=2000-2359;override=C.secret
"""
new = """version=1
default=ignore
user=A;days=Mo-Fr;time=0800-1400;secret=A.secret
user=B;days=Mo-Fr;time=1400-2000;secret=B.secret
user=C;days=Mo-Fr;time=2000-0200;secret=C.secret
"""
if old not in text:
    if new in text:
        raise SystemExit(0)
    raise SystemExit("schedule override configuration example not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
