"""The vault: what's stored on disk (encrypted) and the unlocked copy in memory.

vault.json (safe to sync — everything secret is sealed):
    format, account (Jace user, plaintext), kdf + salt, wrappedKey (vault key sealed with
    the KEK), keyChangedAt, data (the whole vault sealed with the vault key), updatedAt
device.json (this computer only, 0600): the Secret Key, the Jace token, paired extensions.

The vault key never changes, so changing your master password only re-wraps it,
and another device that's still unlocked can keep decrypting synced copies.
"""
import copy
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone

from . import crypto, data_dir, write_private

FORMAT = "jace-passwords/1"
AAD_KEY = b"jace-passwords:key"
AAD_DATA = b"jace-passwords:data"

ITEM_TYPES = ("login", "card", "note", "identity", "alias")

DEFAULT_SETTINGS = {
    "autoLockMinutes": 10,
    "clipboardClearSeconds": 30,
    "travelMode": False,
    "theme": "system",
    "aliasBase": "",
    "lockOnSleep": True,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_id() -> str:
    return uuid.uuid4().hex


class VaultError(Exception):
    pass


class Locked(VaultError):
    pass


def empty_data() -> dict:
    t = now_iso()
    return {
        "vaults": [
            {"id": new_id(), "name": "Personal", "icon": "🔐", "color": "#3ddc84", "travelSafe": True, "createdAt": t, "updatedAt": t},
        ],
        "items": [],
        "settings": dict(DEFAULT_SETTINGS),
        "generatorHistory": [],
        "createdAt": t,
    }


class Vault:
    def __init__(self, directory=None):
        self.dir = directory or data_dir()
        self.path = self.dir / "vault.json"
        self.device_path = self.dir / "device.json"
        self.lock_ = threading.RLock()
        self._key: bytes | None = None
        self._data: dict | None = None
        self._file_meta: dict = {}
        self.last_activity = time.time()

    # ---------- files ----------
    def exists(self) -> bool:
        return self.path.exists()

    def read_file(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def device(self) -> dict:
        try:
            return json.loads(self.device_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def save_device(self, dev: dict) -> None:
        write_private(self.device_path, json.dumps(dev, indent=2))

    def update_device(self, **changes) -> dict:
        with self.lock_:
            dev = self.device()
            for k, v in changes.items():
                if v is None:
                    dev.pop(k, None)
                else:
                    dev[k] = v
            self.save_device(dev)
            return dev

    # ---------- state ----------
    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def touch(self):
        self.last_activity = time.time()

    def require(self) -> dict:
        if self._data is None:
            raise Locked("The vault is locked.")
        self.touch()
        return self._data

    def settings(self) -> dict:
        s = dict(DEFAULT_SETTINGS)
        if self._data:
            s.update(self._data.get("settings", {}))
        return s

    # ---------- create / unlock / lock ----------
    def create(self, password: str, account: dict | None, secret_key: str | None = None) -> str:
        if len(password) < 10:
            raise VaultError("Use at least 10 characters for your master password.")
        with self.lock_:
            secret_key = secret_key or crypto.new_secret_key()
            vault_key = os.urandom(32)
            self._key, self._data = vault_key, empty_data()
            self._wrap(password, secret_key, account)
            self.update_device(secretKey=secret_key)
            self.save()
            return secret_key

    def _wrap(self, password, secret_key, account=None):
        salt = os.urandom(16)
        kdf = dict(crypto.DEFAULT_KDF)
        kek = crypto.derive_kek(password, secret_key, salt, kdf)
        self._file_meta = {
            "format": FORMAT,
            "account": account if account is not None else self._file_meta.get("account"),
            "kdf": kdf,
            "salt": crypto.b64e(salt),
            "wrappedKey": crypto.seal(kek, self._key, AAD_KEY),
            "keyChangedAt": now_iso(),
        }

    def unlock(self, password: str, secret_key: str | None = None, file: dict | None = None) -> None:
        """Unlocks the vault on disk (or `file`, a synced copy being restored)."""
        with self.lock_:
            f = file or self.read_file()
            if f.get("format") != FORMAT:
                raise VaultError("This isn't a Jace Passwords vault.")
            sk = secret_key or self.device().get("secretKey")
            if not sk:
                raise VaultError("Enter your Secret Key (it's on your Emergency Kit).")
            kek = crypto.derive_kek(password, sk, crypto.b64d(f["salt"]), f["kdf"])
            key = crypto.open_sealed(kek, f["wrappedKey"], AAD_KEY)
            data = crypto.open_json(key, f["data"], AAD_DATA)
            self._key, self._data = key, data
            self._file_meta = {k: v for k, v in f.items() if k not in ("data", "updatedAt")}
            if secret_key:
                self.update_device(secretKey=secret_key)
            if file is not None:
                self.save()
            self.touch()

    def lock(self) -> None:
        with self.lock_:
            self._key, self._data = None, None

    def change_password(self, current: str, new: str) -> None:
        with self.lock_:
            self.require()
            f = self.read_file()
            sk = self.device().get("secretKey", "")
            kek = crypto.derive_kek(current, sk, crypto.b64d(f["salt"]), f["kdf"])
            crypto.open_sealed(kek, f["wrappedKey"], AAD_KEY)  # raises if wrong
            if len(new) < 10:
                raise VaultError("Use at least 10 characters for your master password.")
            self._wrap(new, sk)
            self.save()

    def verify_password(self, password: str) -> bool:
        try:
            f = self.read_file()
            kek = crypto.derive_kek(password, self.device().get("secretKey", ""), crypto.b64d(f["salt"]), f["kdf"])
            crypto.open_sealed(kek, f["wrappedKey"], AAD_KEY)
            return True
        except Exception:
            return False

    # ---------- saving ----------
    def file_dict(self) -> dict:
        with self.lock_:
            self.require()
            return {**self._file_meta, "data": crypto.seal_json(self._key, self._data, AAD_DATA), "updatedAt": now_iso()}

    def save(self) -> None:
        with self.lock_:
            write_private(self.path, json.dumps(self.file_dict(), indent=1))

    def set_account(self, account: dict | None) -> None:
        with self.lock_:
            self._file_meta["account"] = account
            if self.unlocked:
                self.save()

    def account(self) -> dict | None:
        try:
            return self.read_file().get("account")
        except (OSError, ValueError):
            return None

    # ---------- reading ----------
    def snapshot(self) -> dict:
        """The unlocked vault for the UI. In Travel Mode, vaults not marked safe are hidden."""
        with self.lock_:
            d = copy.deepcopy(self.require())
            if d.get("settings", {}).get("travelMode"):
                safe = {v["id"] for v in d["vaults"] if v.get("travelSafe")}
                d["vaults"] = [v for v in d["vaults"] if v["id"] in safe]
                d["items"] = [i for i in d["items"] if i.get("vaultId") in safe]
            d["items"] = [i for i in d["items"] if not i.get("purged")]
            for i in d["items"]:  # passkey private keys never leave the vault
                pks = i.get("fields", {}).get("passkeys")
                if pks:
                    i["fields"]["passkeys"] = [{k: v for k, v in p.items() if k != "privateKey"} for p in pks]
            return d

    def visible_items(self, include_trash=False) -> list:
        return [i for i in self.snapshot()["items"] if include_trash or not i.get("deletedAt")]

    def get_item(self, item_id: str) -> dict:
        for i in self.require()["items"]:
            if i["id"] == item_id and not i.get("purged"):
                return i
        raise VaultError("That item doesn't exist.")

    # ---------- items ----------
    def create_item(self, item: dict) -> dict:
        with self.lock_:
            d = self.require()
            if item.get("type") not in ITEM_TYPES:
                raise VaultError("Unknown item type.")
            vault_ids = {v["id"] for v in d["vaults"]}
            t = now_iso()
            new = {
                "id": new_id(),
                "type": item["type"],
                "vaultId": item.get("vaultId") if item.get("vaultId") in vault_ids else d["vaults"][0]["id"],
                "title": (item.get("title") or "").strip()[:200] or "Untitled",
                "favorite": bool(item.get("favorite")),
                "tags": [str(t_)[:40] for t_ in item.get("tags", [])][:20],
                "fields": item.get("fields") or {},
                "passwordHistory": [],
                "createdAt": t,
                "updatedAt": t,
                "passwordChangedAt": t,
            }
            d["items"].append(new)
            self.save()
            return new

    def update_item(self, item_id: str, changes: dict) -> dict:
        with self.lock_:
            d = self.require()
            it = self.get_item(item_id)
            old_pw = it.get("fields", {}).get("password")
            if isinstance(changes.get("fields"), dict):
                # The app window never sees private keys: keep the stored ones; a passkey left
                # out of the list was deleted, and one we don't already have can't be added here.
                stored = {p["credentialId"]: p for p in it.get("fields", {}).get("passkeys", [])}
                kept = [stored[p.get("credentialId")] for p in changes["fields"].get("passkeys") or []
                        if p.get("credentialId") in stored]
                changes = {**changes, "fields": {**changes["fields"], "passkeys": kept}}
                if not kept:
                    changes["fields"].pop("passkeys", None)
            for k in ("title", "favorite", "tags", "fields", "vaultId"):
                if k in changes:
                    if k == "vaultId" and changes[k] not in {v["id"] for v in d["vaults"]}:
                        continue
                    it[k] = changes[k]
            new_pw = it.get("fields", {}).get("password")
            if old_pw and new_pw != old_pw:
                it.setdefault("passwordHistory", []).insert(0, {"password": old_pw, "changedAt": now_iso()})
                it["passwordHistory"] = it["passwordHistory"][:20]
                it["passwordChangedAt"] = now_iso()
            it["updatedAt"] = now_iso()
            self.save()
            return it

    def mark_used(self, item_id: str) -> None:
        with self.lock_:
            it = self.get_item(item_id)
            it["lastUsedAt"] = now_iso()
            it["useCount"] = int(it.get("useCount", 0)) + 1
            self.save()

    def trash_item(self, item_id: str) -> None:
        with self.lock_:
            it = self.get_item(item_id)
            it["deletedAt"] = it["updatedAt"] = now_iso()
            self.save()

    def restore_item(self, item_id: str) -> None:
        with self.lock_:
            it = self.get_item(item_id)
            it.pop("deletedAt", None)
            it["updatedAt"] = now_iso()
            self.save()

    def purge_item(self, item_id: str) -> None:
        """Deletes for good, keeping a tombstone so sync removes it on other devices too."""
        with self.lock_:
            it = self.get_item(item_id)
            for k in list(it):
                if k not in ("id", "vaultId", "type"):
                    del it[k]
            it["purged"] = True
            it["updatedAt"] = now_iso()
            self.save()

    def empty_trash(self) -> int:
        with self.lock_:
            ids = [i["id"] for i in self.require()["items"] if i.get("deletedAt") and not i.get("purged")]
            for i in ids:
                self.purge_item(i)
            return len(ids)

    # ---------- passkeys ----------
    def passkeys_for(self, rp_id: str) -> list[tuple[dict, dict]]:
        """(item, passkey) pairs for a relying party, from the vaults you can see right now."""
        visible = {i["id"] for i in self.visible_items()}
        out = []
        for i in self.require()["items"]:
            if i["id"] in visible:
                for p in i.get("fields", {}).get("passkeys", []):
                    if p.get("rpId") == rp_id:
                        out.append((i, p))
        return out

    def save_passkey(self, passkey: dict, rp_name: str) -> dict:
        """Adds a passkey to the login for that site and username (made if needed).
        A passkey for the same account (user handle) on the same site is replaced."""
        from .security import matches, hostname
        with self.lock_:
            passkey = {**passkey, "createdAt": now_iso()}
            url = "https://" + passkey["rpId"]
            for i, p in self.passkeys_for(passkey["rpId"]):
                if p.get("userHandle") == passkey["userHandle"]:
                    i["fields"]["passkeys"] = [x for x in i["fields"]["passkeys"] if x is not p]
            target = None
            for i in self.visible_items():
                f = i.get("fields", {})
                if matches(i, url) and (f.get("username", "") in ("", passkey["userName"])):
                    target = self.get_item(i["id"])
                    break
            if target is None:
                target = self.create_item({"type": "login", "title": rp_name or hostname(url),
                                           "fields": {"username": passkey["userName"], "urls": [url]}})
            f = target.setdefault("fields", {})
            if not f.get("username"):
                f["username"] = passkey["userName"]
            f.setdefault("passkeys", []).append(passkey)
            target["updatedAt"] = now_iso()
            self.save()
            return target

    def touch_passkey(self, item: dict, passkey: dict) -> None:
        with self.lock_:
            passkey["lastUsedAt"] = item["lastUsedAt"] = now_iso()
            item["useCount"] = int(item.get("useCount", 0)) + 1
            self.save()

    # ---------- vaults ----------
    def create_vault(self, v: dict) -> dict:
        with self.lock_:
            d = self.require()
            t = now_iso()
            new = {"id": new_id(), "name": (v.get("name") or "Vault").strip()[:60], "icon": v.get("icon") or "🗂️",
                   "color": v.get("color") or "#3ddc84", "travelSafe": bool(v.get("travelSafe", False)),
                   "createdAt": t, "updatedAt": t}
            d["vaults"].append(new)
            self.save()
            return new

    def update_vault(self, vault_id: str, changes: dict) -> dict:
        with self.lock_:
            for v in self.require()["vaults"]:
                if v["id"] == vault_id:
                    for k in ("name", "icon", "color", "travelSafe"):
                        if k in changes:
                            v[k] = changes[k]
                    v["updatedAt"] = now_iso()
                    self.save()
                    return v
            raise VaultError("That vault doesn't exist.")

    def delete_vault(self, vault_id: str) -> None:
        with self.lock_:
            d = self.require()
            live = [v for v in d["vaults"] if not v.get("deleted")]
            if len(live) <= 1:
                raise VaultError("You need at least one vault.")
            for v in d["vaults"]:
                if v["id"] == vault_id:
                    v["deleted"] = True
                    v["updatedAt"] = now_iso()
            d["vaults"] = [v for v in d["vaults"] if not v.get("deleted")]
            for i in d["items"]:
                if i.get("vaultId") == vault_id and not i.get("purged"):
                    i["deletedAt"] = i["updatedAt"] = now_iso()
                    i["vaultId"] = d["vaults"][0]["id"]
            self.save()

    def update_settings(self, changes: dict) -> dict:
        with self.lock_:
            d = self.require()
            s = d.setdefault("settings", dict(DEFAULT_SETTINGS))
            for k, v in changes.items():
                if k in DEFAULT_SETTINGS:
                    s[k] = v
            s["updatedAt"] = now_iso()
            self.save()
            return s

    def remember_generated(self, password: str) -> None:
        with self.lock_:
            d = self.require()
            h = d.setdefault("generatorHistory", [])
            h.insert(0, {"password": password, "createdAt": now_iso()})
            del h[25:]
            self.save()

    # ---------- sync merge ----------
    def merge_remote(self, remote_file: dict) -> bool:
        """Merges a synced copy into this one. Newest change wins per item and vault.
        Returns True if anything changed here."""
        with self.lock_:
            d = self.require()
            try:
                remote = crypto.open_json(self._key, remote_file["data"], AAD_DATA)
            except crypto.CryptoError as e:
                raise VaultError("The vault on Jace was made with a different key. "
                                 "Sign out of Jace or reset its copy in Settings.") from e
            changed = False
            for coll in ("items", "vaults"):
                mine = {x["id"]: x for x in d.get(coll, [])}
                for r in remote.get(coll, []):
                    m = mine.get(r["id"])
                    if m is None or r.get("updatedAt", "") > m.get("updatedAt", ""):
                        mine[r["id"]] = r
                        changed = True
                d[coll] = list(mine.values())
            rs, ls = remote.get("settings", {}), d.get("settings", {})
            if rs.get("updatedAt", "") > ls.get("updatedAt", ""):
                d["settings"] = rs
                changed = True
            # A newer master password from another device wins too.
            if remote_file.get("keyChangedAt", "") > self._file_meta.get("keyChangedAt", ""):
                for k in ("kdf", "salt", "wrappedKey", "keyChangedAt"):
                    self._file_meta[k] = remote_file[k]
                changed = True
            if changed:
                self.save()
            return changed
