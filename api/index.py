"""Vercel entry point: the same server, read-only and behind a password.

Every request comes here, static files included. That is deliberate -- routing `web/`
straight to Vercel's static hosting would serve app.js, audit.html and the whole
interface to anyone with the URL, with the password guarding only the API. The auth
check has to sit in front of everything or it guards nothing.

Three things are forced here rather than configured, because a hosted build must not be
able to do them whatever the environment says:

  read-only    Vercel's filesystem is read-only apart from /tmp, and /tmp does not
               survive between invocations. An approval would fail, or -- far worse --
               appear to succeed and vanish. Signing stays local, where the files it
               writes are under review and under git.
  no ROBOT     the SPARQL rebuild shells out to a 79 MB jar and a JDK. Neither is here.
  fail closed  with no password set, every request is refused. An auth check that falls
               open when misconfigured is worse than none, because it looks like one.

Cold start is not a problem: json.load of the 16 MB index is 0.06s and the whole
Resolver builds in 0.15s, so a cold invocation pays a sixth of a second.
"""
import base64, hmac, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# traverse.py opens "config/..." and "data/..." relative, so the directory is set once
# here rather than making ~30 call sites bundle-aware -- same reasoning as the .app.
os.chdir(ROOT)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "build"))
os.environ["FOODON_READ_ONLY"] = "1"

import serve                                            # noqa: E402  builds the graph

USER = os.environ.get("FOODON_USER", "taster")
PASSWORD = os.environ.get("FOODON_PASSWORD", "")
WEB = os.path.join(ROOT, "web")


class handler(serve.Handler):
    def __init__(self, *a, **kw):
        # serve.Handler passes directory="web", which is relative to the working
        # directory. Absolute here, because a serverless invocation's cwd is not ours
        # to assume.
        kw.pop("directory", None)
        super(serve.Handler, self).__init__(*a, directory=WEB, **kw)

    def _denied(self, why):
        body = why.encode()
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="FoodOn avoidance graph"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self):
        if not PASSWORD:
            self._denied("No password is configured for this deployment, so nothing is "
                         "served. Set FOODON_PASSWORD in the Vercel project.")
            return False
        got = self.headers.get("Authorization", "")
        if got.startswith("Basic "):
            try:
                raw = base64.b64decode(got[6:]).decode("utf-8", "replace")
            except Exception:
                raw = ""
            user, _, pw = raw.partition(":")
            # compare_digest on both halves: a plain == leaks length and content through
            # timing, and the whole point of the password is that guessing is expensive
            if (hmac.compare_digest(user, USER)
                    and hmac.compare_digest(pw, PASSWORD)):
                return True
        self._denied("This deployment is password-protected.")
        return False

    def do_GET(self):
        if not self._authorised():
            return
        return super().do_GET()

    def do_POST(self):
        if not self._authorised():
            return
        return super().do_POST()
