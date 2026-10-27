import re
import urllib.request

HOST = "192.168.1.71"

for path in (
    "/net/net/protocol.html",
    "/general/status.html",
    "/admin/default.html",
    "/admin/password.html",
):
    b = urllib.request.urlopen(f"http://{HOST}{path}", timeout=8).read().decode(
        "latin-1", "replace"
    )
    print("====", path, "len", len(b))
    forms = re.findall(r"<form[\s\S]*?</form>", b, flags=re.I)
    print("forms", len(forms))
    for f in forms[:3]:
        print(f[:900])
        print("---")
    hrefs = re.findall(r"""href=["']([^"']+)["']""", b, flags=re.I)
    for h in hrefs:
        if any(k in h.lower() for k in ("login", "pass", "auth", "cookie")):
            print("href", h)
    for m in re.finditer(
        r".{0,50}(AuthCookie|LoginPassword|password|Ndc|Loginform).{0,50}",
        b,
        flags=re.I,
    ):
        print("ctx", m.group(0).replace("\n", " ")[:140])
