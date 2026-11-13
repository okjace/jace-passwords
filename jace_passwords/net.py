"""HTTPS for every request the app makes (Jace, Have I Been Pwned, GitHub update checks).

The packaged apps carry their own OpenSSL, which looks for trusted certificates where the build
machine (Ubuntu) keeps them: /usr/lib/ssl. Jace OS, Arch, Fedora and others keep them elsewhere,
so without this every request failed as "Couldn't reach Jace". Like Jace Social, use the bundled
certifi set plus the system's own.
"""
import os
import ssl
import urllib.request

SYSTEM_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Arch, Jace OS
                  "/etc/pki/tls/certs/ca-bundle.crt",      # Fedora, RHEL
                  "/etc/ssl/ca-bundle.pem",                # openSUSE
                  "/etc/ssl/cert.pem")                     # Alpine, macOS

_ctx: ssl.SSLContext | None = None


def tls() -> ssl.SSLContext:
    global _ctx
    if _ctx is None:
        ctx = ssl.create_default_context()
        try:
            import certifi
            ctx.load_verify_locations(cafile=certifi.where())
        except (ImportError, OSError, ssl.SSLError):
            pass
        for path in SYSTEM_BUNDLES:
            if os.path.isfile(path):
                try:
                    ctx.load_verify_locations(cafile=path)
                    break
                except (OSError, ssl.SSLError):
                    pass
        _ctx = ctx
    return _ctx


def urlopen(req, timeout=30):
    return urllib.request.urlopen(req, timeout=timeout, context=tls())
