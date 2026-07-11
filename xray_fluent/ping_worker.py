from __future__ import annotations

import socket
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait

from PyQt6.QtCore import QThread, pyqtSignal

from .engines.singbox.config_builder import is_singbox_endpoint_node
from .models import Node


_MAX_PING_WORKERS = 16


def tcp_ping(host: str, port: int, timeout: float = 2.0) -> int | None:
    if not host or not port:
        return None
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000.0
            return int(elapsed)
    except OSError:
        return None


def ping_node(node: Node, timeout: float = 2.0) -> int | None:
    """TCP-пинг ноды; endpoint-ноды (UDP-only, напр. WireGuard/AWG) не пингуются."""
    if is_singbox_endpoint_node(node):
        return None
    return tcp_ping(node.server, node.port, timeout)


def apply_ping_measurement(node: Node, ping_ms: int | None) -> None:
    """Применяет результат TCP-пинга к ноде.

    Endpoint-ноды (UDP-only) не измеряются по TCP: ping_ms остаётся None,
    is_alive не сбрасывается в False.
    """
    if is_singbox_endpoint_node(node):
        node.ping_ms = None
        return
    node.ping_ms = ping_ms
    if ping_ms is not None or node.is_alive is None:
        node.is_alive = ping_ms is not None


class PingWorker(QThread):
    result = pyqtSignal(str, object)
    progress = pyqtSignal(int, int)  # current, total
    completed = pyqtSignal()

    def __init__(self, nodes: list[Node], timeout: float = 2.0):
        super().__init__()
        self._nodes = nodes
        self._timeout = timeout
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        total = len(self._nodes)
        if total == 0:
            self.completed.emit()
            return

        max_workers = min(_MAX_PING_WORKERS, total)
        executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ping")
        pending: dict[Future[int | None], str] = {}
        iterator = iter(self._nodes)
        completed = 0

        try:
            for _ in range(max_workers):
                node = next(iterator, None)
                if node is None:
                    break
                future = executor.submit(ping_node, node, self._timeout)
                pending[future] = node.id

            while pending and not self._cancelled:
                done, _ = wait(tuple(pending), timeout=0.1, return_when=FIRST_COMPLETED)
                if not done:
                    continue

                for future in done:
                    node_id = pending.pop(future)
                    try:
                        ms = future.result()
                    except Exception:
                        ms = None

                    completed += 1
                    self.result.emit(node_id, ms)
                    self.progress.emit(completed, total)

                    if self._cancelled:
                        break

                    next_node = next(iterator, None)
                    if next_node is not None:
                        next_future = executor.submit(ping_node, next_node, self._timeout)
                        pending[next_future] = next_node.id

            if self._cancelled:
                for future in pending:
                    future.cancel()
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        self.completed.emit()
