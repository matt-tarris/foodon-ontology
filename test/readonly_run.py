#!/usr/bin/env python3
"""A read-only deployment must refuse every write, and refuse it at the server.

The audit UI disables its own buttons when it sees the flag, but that is a courtesy to
the reviewer, not a control: anyone can POST. So the gate is asserted here against a
real server over real HTTP, because that is the only place it actually holds.

The distinction being pinned is that read-only is WEAKER than explore-only. The .app
hides the audit layer entirely; a hosted build shows it -- the queue and the signed
decisions are the most interesting thing in the project -- and simply cannot write.
`/api/audit/preview` is the one POST that survives, because it reports what an edit
WOULD do and writes nothing.
"""
import json, os, subprocess, sys, time, urllib.error, urllib.request

PORT = 8793
fails, checks = [], 0


def req(path, method="GET", body=None):
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method,
                               data=json.dumps(body).encode() if body else None,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=20) as f:
            return f.status, f.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


env = dict(os.environ, FOODON_READ_ONLY="1")
srv = subprocess.Popen([sys.executable, "serve.py", str(PORT)], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(80):
        try:
            if req("/api/health")[0] == 200:
                break
        except Exception:
            time.sleep(0.25)
    else:
        print("server never came up"); sys.exit(1)

    checks += 1
    if not json.loads(req("/api/health")[1]).get("read_only"):
        fails.append("/api/health does not report read_only, so the UI cannot know to "
                     "disable the controls it is about to fail")

    # reads: the whole point of this mode is that the governance layer stays visible
    for path in ("/", "/audit.html", "/audit.js", "/api/audit", "/api/audit/ingredients",
                 "/api/audit/vocabulary", "/api/query?q=milk"):
        checks += 1
        code = req(path)[0]
        if code != 200:
            fails.append(f"GET {path} returned {code}; a read-only build must still "
                         f"show everything a local one shows")

    # writes: every one of these lands in a governed file
    for path in ("/api/audit/edit", "/api/audit/ingredients/review",
                 "/api/audit/rebuild"):
        checks += 1
        code, body = req(path, "POST", {})
        if code != 403:
            fails.append(f"POST {path} returned {code}, not 403 -- a hosted filesystem "
                         f"keeps neither the file nor the review it belongs to")
        elif not json.loads(body).get("read_only"):
            fails.append(f"POST {path} refused without saying why")

    # the exception, and it must stay an exception
    checks += 1
    code, _ = req("/api/audit/preview", "POST",
                  {"subject": "x", "predicate": "y", "object": "z"})
    if code == 403:
        fails.append("/api/audit/preview is refused; it reports what an edit WOULD do "
                     "and writes nothing, and it is what stops a wrong IRI landing")
finally:
    srv.terminate()
    srv.wait(timeout=10)

if fails:
    print(f"\n{len(fails)} FAILURES:")
    for f in fails:
        print("   -", f)
    sys.exit(1)
print(f"\nPASS - {checks} assertions")
