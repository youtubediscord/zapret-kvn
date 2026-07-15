from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from uuid import uuid4

from .constants import CONFIGS_DIR, TEMPLATE_UPDATE_BUNDLE_DIR, TEMPLATES_DIR


SUPPORTED_ENGINES = ("sing-box", "xray")


@dataclass(frozen=True)
class TemplateSyncResult:
    templates_updated: tuple[str, ...] = ()
    configs_updated: tuple[str, ...] = ()
    configs_preserved: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.templates_updated or self.configs_updated)


def _same_json_document(left: Path, right: Path) -> bool:
    try:
        left_payload = json.loads(left.read_text(encoding="utf-8-sig"))
        right_payload = json.loads(right.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        try:
            return left.read_bytes() == right.read_bytes()
        except OSError:
            return False
    return left_payload == right_payload


def _same_bytes(left: Path, right: Path) -> bool:
    try:
        return left.read_bytes() == right.read_bytes()
    except OSError:
        return False


def _atomic_copy(source: Path, target: Path) -> bool:
    payload = source.read_bytes()
    if target.is_file() and target.read_bytes() == payload:
        return False

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_bytes(payload)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def sync_packaged_templates(
    *,
    bundle_dir: Path = TEMPLATE_UPDATE_BUNDLE_DIR,
    templates_dir: Path = TEMPLATES_DIR,
    configs_dir: Path = CONFIGS_DIR,
) -> TemplateSyncResult:
    """Install shipped templates and refresh only untouched active copies.

    The self-updater deliberately preserves ``data/``. Release builds therefore
    carry the current native JSON templates under ``assets/template-update``.
    Before replacing a built-in template, compare its previous installed text
    with the same-path active config. An equivalent active copy is still stock
    and follows the new template; a different user-edited config is preserved.
    """

    if not bundle_dir.is_dir():
        return TemplateSyncResult()

    templates_updated: list[str] = []
    configs_updated: list[str] = []
    configs_preserved: list[str] = []

    for engine in SUPPORTED_ENGINES:
        bundled_root = bundle_dir / engine
        if not bundled_root.is_dir():
            continue

        for bundled_path in sorted(bundled_root.rglob("*.json")):
            if not bundled_path.is_file():
                continue

            relative = bundled_path.relative_to(bundled_root)
            key = f"{engine}/{relative.as_posix()}"
            installed_template = templates_dir / engine / relative
            active_config = configs_dir / engine / relative
            template_will_change = not _same_bytes(installed_template, bundled_path)
            active_matches_previous_template = (
                installed_template.is_file()
                and active_config.is_file()
                and _same_json_document(installed_template, active_config)
            )

            # Refresh the active copy first. If startup is interrupted between
            # the two atomic writes, the active config is already on the safe
            # new version and the template write is retried next launch.
            if active_matches_previous_template and _atomic_copy(bundled_path, active_config):
                configs_updated.append(key)
            elif (
                template_will_change
                and installed_template.is_file()
                and active_config.is_file()
                and not _same_json_document(active_config, bundled_path)
            ):
                configs_preserved.append(key)

            if _atomic_copy(bundled_path, installed_template):
                templates_updated.append(key)

    return TemplateSyncResult(
        templates_updated=tuple(templates_updated),
        configs_updated=tuple(configs_updated),
        configs_preserved=tuple(configs_preserved),
    )
