from __future__ import annotations

import json
from pathlib import Path

from .constants import (
    CONFIGS_DIR,
    DATA_DIR,
    LOG_DIR,
    RUNTIME_DIR,
    SINGBOX_CONFIGS_DIR,
    SINGBOX_PATH_DEFAULT,
    SINGBOX_TEMPLATES_DIR,
    STATE_FILE,
    XRAY_CONFIGS_DIR,
    XRAY_TEMPLATES_DIR,
    XRAY_PATH_DEFAULT,
)
from .models import AppState
from .path_utils import normalize_configured_path
from .security import (
    decode_encrypted,
    decrypt_with_passphrase,
    encrypt_with_passphrase,
    is_passphrase_encrypted,
)


class PassphraseRequired(Exception):
    pass


class StateStorage:
    def __init__(self, state_file: Path = STATE_FILE):
        self.state_file = state_file
        self._passphrase: str = ""
        self._ensure_dirs()

    @property
    def passphrase(self) -> str:
        return self._passphrase

    @passphrase.setter
    def passphrase(self, value: str) -> None:
        self._passphrase = value

    def _ensure_dirs(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        SINGBOX_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        XRAY_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        SINGBOX_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        XRAY_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def _default_state(self) -> AppState:
        state = AppState()
        return self._normalize_state_paths(state)

    def _normalize_state_paths(self, state: AppState) -> AppState:
        state.settings.xray_path = normalize_configured_path(
            state.settings.xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        state.settings.singbox_path = normalize_configured_path(
            state.settings.singbox_path,
            default_path=SINGBOX_PATH_DEFAULT,
            migrate_default_location=True,
        )
        return state

    def _serialize_state(self, state: AppState) -> str:
        payload = state.to_dict()
        settings_payload = dict(payload.get("settings") or {})
        settings_payload["xray_path"] = normalize_configured_path(
            settings_payload.get("xray_path"),
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        settings_payload["singbox_path"] = normalize_configured_path(
            settings_payload.get("singbox_path"),
            default_path=SINGBOX_PATH_DEFAULT,
            migrate_default_location=True,
        )
        payload["settings"] = settings_payload
        return json.dumps(payload, ensure_ascii=True, indent=2)

    def is_encrypted(self) -> bool:
        if not self.state_file.exists():
            return False
        raw = self.state_file.read_text(encoding="utf-8").strip()
        return is_passphrase_encrypted(raw)

    def load(self) -> AppState:
        self._ensure_dirs()
        if not self.state_file.exists():
            return self._default_state()

        raw_text = self.state_file.read_text(encoding="utf-8").strip()
        if not raw_text:
            return self._default_state()

        payload: dict

        # Passphrase-encrypted format
        if is_passphrase_encrypted(raw_text):
            if not self._passphrase:
                raise PassphraseRequired()
            decrypted = decrypt_with_passphrase(raw_text, self._passphrase)
            payload = json.loads(decrypted.decode("utf-8"))

        # Plain JSON
        elif raw_text.startswith("{"):
            payload = json.loads(raw_text)

        # Legacy DPAPI format — try migration
        else:
            try:
                decoded = decode_encrypted(raw_text).decode("utf-8")
                payload = json.loads(decoded)
            except Exception:
                try:
                    payload = json.loads(raw_text)
                except json.JSONDecodeError:
                    return self._default_state()

        state = AppState.from_dict(payload)
        return self._normalize_state_paths(state)

    def save(self, state: AppState) -> None:
        self._ensure_dirs()
        payload = self._serialize_state(state)

        if self._passphrase:
            content = encrypt_with_passphrase(payload.encode("utf-8"), self._passphrase)
        else:
            content = payload

        tmp_file = self.state_file.with_suffix(".tmp")
        tmp_file.write_text(content, encoding="utf-8")
        tmp_file.replace(self.state_file)

    def export_backup(self, path: Path, passphrase: str = "") -> None:
        state = self.load()
        payload = self._serialize_state(state)
        if passphrase:
            content = encrypt_with_passphrase(payload.encode("utf-8"), passphrase)
        else:
            content = payload
        path.write_text(content, encoding="utf-8")

    def import_backup(self, path: Path, passphrase: str = "") -> AppState:
        raw = path.read_text(encoding="utf-8").strip()
        if is_passphrase_encrypted(raw):
            if not passphrase:
                raise PassphraseRequired()
            decrypted = decrypt_with_passphrase(raw, passphrase)
            payload = json.loads(decrypted.decode("utf-8"))
        else:
            payload = json.loads(raw)
        return self._normalize_state_paths(AppState.from_dict(payload))
