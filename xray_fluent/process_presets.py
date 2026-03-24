from __future__ import annotations

from dataclasses import dataclass

from qfluentwidgets import FluentIcon as FIF


@dataclass(frozen=True, slots=True)
class ProcessPreset:
    id: str
    name: str
    icon: FIF
    description: str
    processes: tuple[str, ...]
    default_action: str  # "proxy" | "direct"


PROCESS_PRESETS: tuple[ProcessPreset, ...] = (
    # ── Popular apps (default: proxy — route through VPN) ──
    ProcessPreset(
        id="telegram",
        name="Telegram",
        icon=FIF.CHAT,
        description="Telegram, AyuGram, Unigram, Kotatogram",
        processes=("Telegram.exe", "AyuGram.exe", "Unigram.exe", "Kotatogram.exe"),
        default_action="proxy",
    ),
    ProcessPreset(
        id="discord",
        name="Discord",
        icon=FIF.MICROPHONE,
        description="Discord, BetterDiscord, Vesktop",
        processes=("Discord.exe", "Vesktop.exe"),
        default_action="proxy",
    ),
    ProcessPreset(
        id="browsers",
        name="Браузеры",
        icon=FIF.GLOBE,
        description="Chrome, Firefox, Edge, Opera, Brave, Vivaldi, Яндекс",
        processes=(
            "chrome.exe", "firefox.exe", "msedge.exe",
            "opera.exe", "brave.exe", "vivaldi.exe",
            "browser.exe",  # Yandex Browser
        ),
        default_action="proxy",
    ),
    ProcessPreset(
        id="spotify",
        name="Spotify",
        icon=FIF.MUSIC,
        description="Spotify",
        processes=("Spotify.exe",),
        default_action="proxy",
    ),

    # ── Windows system (default: direct — bypass VPN to reduce server load) ──
    ProcessPreset(
        id="windows_system",
        name="Windows система",
        icon=FIF.SETTING,
        description="svchost, explorer, dwm, службы, обновления",
        processes=(
            "svchost.exe",
            "explorer.exe",
            "dwm.exe",
            "csrss.exe",
            "taskhostw.exe",
            "sihost.exe",
            "ctfmon.exe",
            "fontdrvhost.exe",
            "dllhost.exe",
            "conhost.exe",
            "audiodg.exe",
            "spoolsv.exe",
            "SearchApp.exe",
            "SearchHost.exe",
            "RuntimeBroker.exe",
            "LockApp.exe",
            "StartMenuExperienceHost.exe",
            "ShellExperienceHost.exe",
            "TextInputHost.exe",
            "backgroundTaskHost.exe",
            "ApplicationFrameHost.exe",
            "UserOOBEBroker.exe",
            "SystemSettings.exe",
            "WUDFHost.exe",
        ),
        default_action="direct",
    ),
    ProcessPreset(
        id="windows_defender",
        name="Windows Defender",
        icon=FIF.CERTIFICATE,
        description="Антивирус, SmartScreen, обновления безопасности",
        processes=(
            "MsMpEng.exe",
            "NisSrv.exe",
            "SecurityHealthService.exe",
            "SecurityHealthSystray.exe",
            "MpCmdRun.exe",
            "smartscreen.exe",
        ),
        default_action="direct",
    ),
    ProcessPreset(
        id="windows_update",
        name="Windows Update",
        icon=FIF.UPDATE,
        description="Обновления Windows, доставка, BITS",
        processes=(
            "wuauclt.exe",
            "WaaSMedicAgent.exe",
            "UsoClient.exe",
            "musNotification.exe",
            "musNotificationUx.exe",
            "TiWorker.exe",
            "TrustedInstaller.exe",
        ),
        default_action="direct",
    ),
    ProcessPreset(
        id="onedrive",
        name="OneDrive",
        icon=FIF.CLOUD,
        description="OneDrive синхронизация",
        processes=("OneDrive.exe", "OneDriveSetup.exe"),
        default_action="direct",
    ),
)


PROCESS_PRESETS_BY_ID: dict[str, ProcessPreset] = {p.id: p for p in PROCESS_PRESETS}
