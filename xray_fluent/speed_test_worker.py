"""Воркер тестирования скорости — измеряет скорость загрузки через каждый прокси-узел."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.request import ProxyHandler, Request

from PyQt6.QtCore import QThread, pyqtSignal

from .config_builder import build_xray_config
from .constants import (
    PROXY_HOST,
    SPEED_TEST_ROUNDS,
    SPEED_TEST_TEMP_HTTP_PORT,
    SPEED_TEST_TEMP_SOCKS_PORT,
    SPEED_TEST_TIMEOUT,
    SPEED_TEST_URL,
)
from .http_utils import build_opener
from .models import AppSettings, Node, RoutingSettings

# Гео-маппинг: код страны → URL тестового файла из ближайшего ЦОД
_GEO_SPEED_URLS: dict[str, str] = {
    "nl": "https://ams.download.datapacket.com/100mb.bin",
    "de": "https://fra.download.datapacket.com/100mb.bin",
    "gb": "https://lon.download.datapacket.com/100mb.bin",
    "uk": "https://lon.download.datapacket.com/100mb.bin",
    "fr": "https://par.download.datapacket.com/100mb.bin",
    "se": "https://sto.download.datapacket.com/100mb.bin",
    "no": "https://osl.download.datapacket.com/100mb.bin",
    "dk": "https://sto.download.datapacket.com/100mb.bin",
    "fi": "https://sto.download.datapacket.com/100mb.bin",
    "at": "https://fra.download.datapacket.com/100mb.bin",
    "ch": "https://fra.download.datapacket.com/100mb.bin",
    "be": "https://ams.download.datapacket.com/100mb.bin",
    "lu": "https://fra.download.datapacket.com/100mb.bin",
    "pl": "https://ber.download.datapacket.com/100mb.bin",
    "cz": "https://ber.download.datapacket.com/100mb.bin",
    "ie": "https://lon.download.datapacket.com/100mb.bin",
    "ru": "https://speedtest.selectel.ru/100MB",
    "us": "https://ams.download.datapacket.com/100mb.bin",
}
_DEFAULT_SPEED_URL = "https://fra.download.datapacket.com/100mb.bin"


def _get_speed_url(country_code: str) -> str:
    """Возвращает URL тестового файла для страны сервера."""
    return _GEO_SPEED_URLS.get(country_code.lower(), _DEFAULT_SPEED_URL)


class SpeedTestWorker(QThread):
    """Тестирует скорость загрузки через каждый узел с помощью временного экземпляра xray."""

    result = pyqtSignal(str, object, bool)   # node_id, speed_mbps (float|None), is_alive
    progress = pyqtSignal(int, int)          # current, total
    node_progress = pyqtSignal(str, int)     # node_id, percent 0..100
    completed = pyqtSignal()

    def __init__(
        self,
        nodes: list[Node],
        xray_path: str,
        routing: RoutingSettings | None = None,
        timeout: float = SPEED_TEST_TIMEOUT,
    ):
        super().__init__()
        self._nodes = list(nodes)
        self._xray_path = xray_path
        self._routing = routing or RoutingSettings()
        self._timeout = timeout
        self._cancelled = False

    def cancel(self) -> None:
        """Отмена тестирования."""
        self._cancelled = True

    # ------------------------------------------------------------------

    def run(self) -> None:
        total = len(self._nodes)
        for i, node in enumerate(self._nodes):
            if self._cancelled:
                break
            self.progress.emit(i + 1, total)
            self.node_progress.emit(node.id, 0)
            speed, alive = self._test_node(node)
            self.node_progress.emit(node.id, 100)
            self.result.emit(node.id, speed, alive)
        self.completed.emit()

    # ------------------------------------------------------------------

    def _test_node(self, node: Node) -> tuple[float | None, bool]:
        """Запускает временный xray, скачивает тестовый файл, возвращает (speed_mbps, is_alive)."""
        if not Path(self._xray_path).is_file():
            return None, False

        # Минимальные настройки для временного xray
        settings = AppSettings()
        settings.socks_port = SPEED_TEST_TEMP_SOCKS_PORT
        settings.http_port = SPEED_TEST_TEMP_HTTP_PORT
        settings.log_level = "none"

        try:
            config = build_xray_config(node, self._routing, settings)
        except Exception:
            return None, False

        # Убираем stats/api — для теста скорости не нужны
        config.pop("stats", None)
        config.pop("api", None)
        config.pop("policy", None)
        config["inbounds"] = [
            ib for ib in config.get("inbounds", [])
            if ib.get("tag") in ("socks-in", "http-in")
        ]
        routing_obj = config.get("routing", {})
        routing_obj["rules"] = [
            r for r in routing_obj.get("rules", [])
            if r.get("inboundTag") != ["api"]
        ]
        config["routing"] = routing_obj
        config["outbounds"] = [
            ob for ob in config.get("outbounds", [])
            if ob.get("tag") != "api"
        ]

        tmp = None
        proc = None
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                prefix="xray_speed_",
                delete=False,
                encoding="utf-8",
            )
            json.dump(config, tmp, ensure_ascii=True)
            tmp.close()

            proc = subprocess.Popen(
                [self._xray_path, "run", "-c", tmp.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )

            # Даём xray время на запуск (с проверкой отмены)
            for _ in range(10):
                if self._cancelled:
                    return None, False
                self.node_progress.emit(node.id, 2 + _ * 2)
                time.sleep(0.1)

            if proc.poll() is not None:
                return None, False

            url = _get_speed_url(node.country_code)
            rounds = max(1, SPEED_TEST_ROUNDS)
            results: list[float] = []
            for round_index in range(rounds):
                if self._cancelled:
                    break
                s = self._measure_speed(url, node.id, round_index, rounds)
                if s is not None and s > 0:
                    results.append(s)

            if not results:
                return None, False

            # Отбрасываем худший замер, берём среднее оставшихся
            if len(results) > 1:
                results.sort()
                results = results[1:]  # убираем самый медленный
            speed = round(sum(results) / len(results), 2)
            return speed, True

        except Exception:
            return None, False
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if tmp:
                try:
                    Path(tmp.name).unlink(missing_ok=True)
                except Exception:
                    pass

    def _measure_speed(self, url: str, node_id: str, round_index: int, total_rounds: int) -> float | None:
        """Скачивает тестовый файл через временный прокси, возвращает скорость в МБ/с."""
        proxy_url = f"http://{PROXY_HOST}:{SPEED_TEST_TEMP_HTTP_PORT}"
        handler = ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = build_opener(handler)

        req = Request(url, headers={"User-Agent": "ZapretKVN/SpeedTest"})

        try:
            start = time.perf_counter()
            total_bytes = 0
            percent_start = 20 + int(70 * round_index / max(total_rounds, 1))
            percent_end = 20 + int(70 * (round_index + 1) / max(total_rounds, 1))
            with opener.open(req, timeout=self._timeout) as resp:
                length_header = resp.headers.get("Content-Length") or ""
                try:
                    total_length = int(length_header)
                except (TypeError, ValueError):
                    total_length = 0
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if self._cancelled:
                        return None

                    if total_length > 0:
                        fraction = min(1.0, total_bytes / total_length)
                    else:
                        fraction = min(1.0, (time.perf_counter() - start) / max(self._timeout, 0.1))

                    percent = percent_start + int((percent_end - percent_start) * fraction)
                    self.node_progress.emit(node_id, max(percent_start, min(percent_end, percent)))

                    if time.perf_counter() - start > self._timeout:
                        break

            elapsed = time.perf_counter() - start
            if elapsed <= 0 or total_bytes <= 0:
                return None

            self.node_progress.emit(node_id, percent_end)
            speed_mbps = (total_bytes / (1024 * 1024)) / elapsed
            return round(speed_mbps, 2)

        except Exception:
            return None
