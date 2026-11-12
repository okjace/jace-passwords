#!/usr/bin/env python3
"""Builds the Jace Passwords web app and deploys it to Vercel (production).

    VERCEL_TOKEN=… python3 packaging/deploy_vercel.py        (asks for the token if it isn't set)

The site is static files (jace_passwords/web, where the vault runs in the browser) plus one
Python function (webapp/api/jace.py: Sign in with Jace and the encrypted sync relay).
GitHub Actions runs this on every push to main when the VERCEL_TOKEN secret is set.
Optional: VERCEL_TEAM_ID (otherwise your only team, or your personal account), VERCEL_PROJECT.
"""
import base64
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dist" / "web"
API = "https://api.vercel.com"
PROJECT = os.environ.get("VERCEL_PROJECT", "jace-passwords")


def build() -> Path:
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(ROOT / "jace_passwords" / "web", OUT)
    shutil.copytree(ROOT / "webapp" / "api", OUT / "api")
    shutil.copy2(ROOT / "webapp" / "vercel.json", OUT / "vercel.json")
    for junk in OUT.rglob("__pycache__"):
        shutil.rmtree(junk)
    return OUT


class Vercel:
    def __init__(self, token: str, team: str | None = None):
        self.token, self.team = token, team

    def call(self, method, path, body=None, query=None):
        q = dict(query or {})
        if self.team:
            q["teamId"] = self.team
        url = API + path + ("?" + urllib.parse.urlencode(q) if q else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:800]
            raise RuntimeError(f"Vercel {method} {path} -> {e.code}: {detail}") from None

    def pick_team(self):
        if self.team:
            return
        teams = self.call("GET", "/v2/teams").get("teams", [])
        if len(teams) == 1:
            self.team = teams[0]["id"]

    def deploy(self, folder: Path) -> dict:
        files = [{"file": p.relative_to(folder).as_posix(), "encoding": "base64",
                  "data": base64.b64encode(p.read_bytes()).decode()}
                 for p in sorted(folder.rglob("*")) if p.is_file()]
        d = self.call("POST", "/v13/deployments", {
            "name": PROJECT, "files": files, "target": "production",
            "projectSettings": {"framework": None, "buildCommand": None, "installCommand": None,
                                "outputDirectory": None, "devCommand": None}},
            query={"skipAutoDetectionConfirmation": "1"})
        print(f"Deploying {d.get('url')} …", flush=True)
        for _ in range(120):
            d = self.call("GET", f"/v13/deployments/{d['id']}")
            if d.get("readyState") in ("READY", "ERROR", "CANCELED"):
                break
            time.sleep(5)
        if d.get("readyState") != "READY":
            raise RuntimeError(f"Deployment {d.get('readyState')}: https://{d.get('url')} (see the Vercel dashboard)")
        return d

    def production_url(self) -> str:
        doms = self.call("GET", f"/v9/projects/{PROJECT}/domains").get("domains", [])
        names = sorted((x["name"] for x in doms if not x.get("redirect")), key=lambda n: (not n.endswith(".vercel.app"), len(n)))
        return f"https://{names[0]}" if names else ""

    def set_env(self, values: dict):
        body = [{"key": k, "value": v, "type": "encrypted", "target": ["production", "preview"]} for k, v in values.items()]
        self.call("POST", f"/v10/projects/{PROJECT}/env", body, query={"upsert": "true"})


def main() -> int:
    token = os.environ.get("VERCEL_TOKEN")
    if not token:
        if not sys.stdin.isatty():
            print("Set VERCEL_TOKEN.", file=sys.stderr)
            return 2
        import getpass
        print("Create a token at https://vercel.com/account/tokens")
        token = getpass.getpass("Vercel token (hidden while you type): ").strip()
    v = Vercel(token, os.environ.get("VERCEL_TEAM_ID"))
    v.pick_team()
    d = v.deploy(build())
    print(f"Live: {v.production_url() or 'https://' + d['url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
