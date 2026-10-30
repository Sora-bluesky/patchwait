"""Read-only Windows evidence for otherwise unreadable walk directories."""

from __future__ import annotations

import ntpath
import re
import sys

from patchwait import locality

APPX_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx"
PACKAGES_KEY = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
PACKAGE_NOTE = "Only Store packages registered for the current user are walked."
PROTECTED_REASON = "listing_and_permissions_denied"
PROTECTED_NOTE = "These folders were not looked into; an administrator must check if they matter."


class PackageReadError(Exception):
    """Registry evidence is incomplete; keep the original unreadable item."""


def read_package_root() -> str | None:
    """Resolve the configured local Appx root anew; never guess it from a name."""
    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, APPX_KEY, 0, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, "PackageRoot")
        if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value, str) or not value:
            raise PackageReadError("PackageRoot: expected a non-empty REG_SZ or REG_EXPAND_SZ string")
        if kind == winreg.REG_EXPAND_SZ:
            value = winreg.ExpandEnvironmentStrings(value)
        drive, rest = ntpath.splitdrive(value)
        if "\0" in value or re.fullmatch(r"[A-Za-z]:", drive) is None or not rest.startswith(("\\", "/")):
            raise PackageReadError("PackageRoot: not an absolute local drive path")
        if locality.windows_drive_type(drive + "\\") not in (3, 6):
            raise PackageReadError("PackageRoot: drive is not local fixed storage or a RAM disk")
        return ntpath.normpath(value)
    except (ImportError, OSError, AttributeError, ValueError) as error:
        raise PackageReadError(f"PackageRoot: {type(error).__name__}") from None


def registered_packages() -> tuple[str, ...]:
    """Subkey names only: PackageRootFolder can point outside the Store root."""
    try:
        import winreg

        names: list[str] = []
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PACKAGES_KEY, 0, winreg.KEY_READ) as key:
            while True:
                try:
                    names.append(winreg.EnumKey(key, len(names)))
                except OSError as error:
                    if getattr(error, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                        break
                    raise
        return tuple(sorted(names))
    except (ImportError, OSError, AttributeError, ValueError) as error:
        raise PackageReadError(f"current-user package repository: {type(error).__name__}") from None


def valid_package_name(name: str) -> bool:
    """One literal Windows filename component, without Win32 name rewriting."""
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}", name) is None or ".." in name or name.endswith("."):
        return False
    stem = name.split(".", 1)[0].upper()
    return stem not in {"CON", "PRN", "AUX", "NUL", *(f"{prefix}{n}" for prefix in ("COM", "LPT") for n in range(1, 10))}


def permissions_access_denied(path: str) -> bool:
    """True only when reading both owner and DACL returns ERROR_ACCESS_DENIED.

    A size probe normally returns ERROR_INSUFFICIENT_BUFFER; that is not a denial.
    The second call must actually read the descriptor before calling it readable.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        library = ctypes.WinDLL("advapi32", use_last_error=True)  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownVariableType]
        get_security = library.GetFileSecurityW  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        get_security.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p,
                                 ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        get_security.restype = ctypes.c_int
        needed = ctypes.c_uint32()
        owner_and_dacl = 0x00000001 | 0x00000004
        if get_security(path, owner_and_dacl, None, 0, ctypes.byref(needed)):
            return False
        error = ctypes.get_last_error()  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownVariableType]
        if error == 5:  # ERROR_ACCESS_DENIED
            return True
        if error != 122 or needed.value == 0:  # ERROR_INSUFFICIENT_BUFFER
            return False
        buffer = ctypes.create_string_buffer(needed.value)
        if get_security(path, owner_and_dacl, buffer, len(buffer), ctypes.byref(needed)):
            return False
        return ctypes.get_last_error() == 5  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownVariableType]
    except (ImportError, AttributeError, OSError, ValueError, MemoryError, OverflowError):
        return False
