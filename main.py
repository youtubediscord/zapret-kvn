from __future__ import annotations

import argparse
import atexit
import faulthandler
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys
import threading

from xray_fluent.subprocess_utils import result_output_text, run_text


STARTUP_LOG_NAME = "startup.log"


class _TeeStream:
    def __init__(self, *streams) -> None:
        self._streams = [stream for stream in streams if stream is not None]

    def write(self, data: str) -> int:
        for stream in self._streams:
            try:
                stream.write(data)
            except Exception:
                pass
        return len(data)

    def flush(self) -> None:
        for stream in self._streams:
            try:
                stream.flush()
            except Exception:
                pass

    def isatty(self) -> bool:
        return any(getattr(stream, "isatty", lambda: False)() for stream in self._streams)

    @property
    def encoding(self) -> str:
        for stream in self._streams:
            encoding = getattr(stream, "encoding", None)
            if encoding:
                return encoding
        return "utf-8"


def _get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


BASE_DIR = _get_base_dir()
STARTUP_LOG_DIR = BASE_DIR / "data" / "logs"
STARTUP_LOG_PATH = STARTUP_LOG_DIR / STARTUP_LOG_NAME
_bootstrap_logger = logging.getLogger("xray_fluent.bootstrap")
_bootstrap_stream = None


def _setup_bootstrap_logging() -> None:
    global _bootstrap_stream

    STARTUP_LOG_DIR.mkdir(parents=True, exist_ok=True)

    if not _bootstrap_logger.handlers:
        handler = RotatingFileHandler(
            STARTUP_LOG_PATH,
            maxBytes=1 * 1024 * 1024,
            backupCount=2,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        _bootstrap_logger.addHandler(handler)
        _bootstrap_logger.setLevel(logging.DEBUG)
        _bootstrap_logger.propagate = False

    if _bootstrap_stream is None:
        _bootstrap_stream = STARTUP_LOG_PATH.open("a", encoding="utf-8", buffering=1)
        sys.stdout = _TeeStream(getattr(sys, "__stdout__", None), _bootstrap_stream)
        sys.stderr = _TeeStream(getattr(sys, "__stderr__", None), _bootstrap_stream)
        try:
            faulthandler.enable(_bootstrap_stream)
        except Exception:
            pass

    _bootstrap_logger.info("----- startup begin -----")
    _bootstrap_logger.info("argv=%s", sys.argv)
    _bootstrap_logger.info("frozen=%s executable=%s", getattr(sys, "frozen", False), sys.executable)
    if sys.platform == "win32":
        try:
            version = sys.getwindowsversion()
            _bootstrap_logger.info(
                "windows_version major=%s minor=%s build=%s platform=%s service_pack=%s",
                version.major,
                version.minor,
                version.build,
                version.platform,
                version.service_pack,
            )
        except Exception:
            _bootstrap_logger.exception("Failed to query Windows version")


def _fatal_error_message() -> str:
    return f"zapret kvn не удалось запустить.\n\nПодробности записаны в:\n{STARTUP_LOG_PATH}"


def _show_fatal_message_box() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, _fatal_error_message(), "zapret kvn", 0x10)
    except Exception:
        pass


def _log_unhandled_exception(exc_type, exc_value, exc_traceback) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    _bootstrap_logger.exception("Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))
    _show_fatal_message_box()


def _log_background_exception(args: threading.ExceptHookArgs) -> None:
    if issubclass(args.exc_type, KeyboardInterrupt):
        return
    _bootstrap_logger.exception(
        "Unhandled background exception",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


def _install_exception_hooks() -> None:
    sys.excepthook = _log_unhandled_exception
    threading.excepthook = _log_background_exception
    atexit.register(_disable_system_proxy_on_exit)
    atexit.register(_log_process_exit)


def _looks_like_app_proxy(proxy_server: str) -> bool:
    value = proxy_server.lower().replace(" ", "")
    return (
        "http=127.0.0.1:" in value
        and "https=127.0.0.1:" in value
        and "socks=127.0.0.1:" in value
    )


def _disable_system_proxy_on_exit() -> None:
    """Safety net: always disable system proxy and clean up TUN adapter."""
    if sys.platform != "win32":
        return
    # Disable system proxy
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                            0, winreg.KEY_READ) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            try:
                proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                proxy_server = ""
        if int(enabled) == 1 and _looks_like_app_proxy(str(proxy_server or "")):
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            _bootstrap_logger.info("System proxy disabled on exit (safety)")
    except Exception:
        pass
    # Disable leftover TUN adapter if our interface is still present.
    try:
        r = run_text(["netsh", "interface", "show", "interface"], timeout=5, creationflags=0x08000000)
        if "ZapretKVN_TUN" in result_output_text(r):
            import subprocess as _sp
            _sp.run(["netsh", "interface", "set", "interface", "ZapretKVN_TUN", "admin=disable"], capture_output=True, timeout=5, creationflags=0x08000000)
            _bootstrap_logger.info("TUN adapter disabled on exit (safety)")
    except Exception:
        pass


def _log_process_exit() -> None:
    _bootstrap_logger.info("----- process exit -----")


def _can_start_in_tray() -> bool:
    try:
        from xray_fluent.storage import StateStorage

        storage = StateStorage()
        if storage.is_encrypted():
            _bootstrap_logger.info("Tray startup disabled: encrypted state requires passphrase")
            return False

        state = storage.load()
        if state.security.enabled:
            _bootstrap_logger.info("Tray startup disabled: master password requires unlock")
            return False
        return True
    except Exception:
        _bootstrap_logger.exception("Failed to preflight tray startup requirements")
        return False


def _hide_console_if_needed() -> None:
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    try:
        import ctypes

        console = ctypes.windll.kernel32.GetConsoleWindow()
        if console:
            ctypes.windll.user32.ShowWindow(console, 0)
            _bootstrap_logger.debug("Console window hidden")
    except Exception:
        _bootstrap_logger.exception("Failed to hide console window")


def _enforce_frozen() -> None:
    if not getattr(sys, "frozen", False):
        raise SystemExit(
            "ОШИБКА: Прямой запуск не поддерживается.\n"
            "Сначала соберите приложение:  python build.py\n"
            "Затем запустите:              dist\\ZapretKVN\\ZapretKVN.exe"
        )


def main() -> int:
    _setup_bootstrap_logging()
    _install_exception_hooks()
    _enforce_frozen()
    _hide_console_if_needed()

    parser = argparse.ArgumentParser(description="zapret kvn")
    parser.add_argument("--tray", action="store_true", help="start in tray")
    args = parser.parse_args()

    _bootstrap_logger.info("parsed arguments: tray=%s", args.tray)
    _bootstrap_logger.info("Importing Qt and application modules")

    import qfluentwidgets  # noqa: F401
    from PyQt6.QtCore import QSize
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QSystemTrayIcon
    from qfluentwidgets import SplashScreen
    from qframelesswindow import StandardTitleBar

    from xray_fluent.constants import APP_NAME
    from xray_fluent.ui.main_window import MainWindow

    _bootstrap_logger.info("Creating QApplication")
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    tray_available = QSystemTrayIcon.isSystemTrayAvailable()
    app.setQuitOnLastWindowClosed(not tray_available)

    start_hidden = args.tray
    if start_hidden and not tray_available:
        _bootstrap_logger.warning("System tray unavailable; disabling tray startup")
        start_hidden = False
    if start_hidden and not _can_start_in_tray():
        _bootstrap_logger.warning("Tray startup requires interactive unlock; showing window instead")
        start_hidden = False
    _bootstrap_logger.info("system tray available=%s start_hidden=%s", tray_available, start_hidden)

    _bootstrap_logger.info("Creating main window shell")
    window = MainWindow(defer_init=not start_hidden)

    splash = None
    if not start_hidden:
        _bootstrap_logger.info("Showing stock splash screen")
        icon = QIcon(":/qfluentwidgets/images/logo.png")
        splash = SplashScreen(icon, window)
        title_bar = StandardTitleBar(splash)
        title_bar.setIcon(window.windowIcon())
        title_bar.setTitle(window.windowTitle())
        splash.setTitleBar(title_bar)
        sz = splash.iconSize()
        scale = max(1, window.logicalDpiX() // 96)
        splash.setIconSize(QSize(sz.width() * scale, sz.height() * scale))
        window.show()
        app.processEvents()
        _bootstrap_logger.info("Initializing main window behind splash")
        window.initialize()
        app.processEvents()
        splash.finish()
    else:
        _bootstrap_logger.info("Creating main window")
        window.initialize()

    mica_enabled = getattr(window, "isMicaEffectEnabled", lambda: False)()
    _bootstrap_logger.info("main window created: mica_enabled=%s", mica_enabled)

    if start_hidden:
        _bootstrap_logger.info("Starting in tray")
        window.hide()
    elif splash is None:
        _bootstrap_logger.info("Showing main window")
        window.show()

    _bootstrap_logger.info("Entering Qt event loop")
    exit_code = app.exec()
    _bootstrap_logger.info("Qt event loop exited with code %s", exit_code)
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        _bootstrap_logger.exception("Fatal startup error")
        _show_fatal_message_box()
        raise SystemExit(1)
