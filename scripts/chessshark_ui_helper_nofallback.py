#!/usr/bin/env python3
"""Unattended, reversible UI driver for the ChessShark registration flow.

This helper only sends VCL button messages inside the ChessShark process.  It
does not start a process, call RunAs, touch UAC/consent.exe, write the target
executable, or modify registration state.  It is deliberately separate from
``chessshark_ui_helper.py`` so the older observer remains a clean rollback
point.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Iterable

import win32con
import win32clipboard
import win32api
import win32gui
import win32process
import psutil


FORM_CLASSES = {
    "TFormUpdateTip",
    "TFormLogin",
    "TFormRegist",
    "TFormConnectAdd",
    "TFormAgreement",
    "TForm1",
    "TApplication",
}

MESSAGEBOX_CLASS = "#32770"
# Enigma Protector's loader warning is a custom modal window rather than a
# Win32 MessageBox.  It appears before the VCL forms and otherwise stalls a
# fast observation run until the operator clicks its ``&OK`` button.
PROTECTOR_WARNING_CLASS = "TEnigmaProtectorLoaderFormMessage.UnicodeClass"
PROTECTOR_WARNING_BUTTON_CLASS = "TEnigmaProtectorLoaderButton.UnicodeClass"
DEFAULT_TARGET_NAME = "ChessShark.exe"


def process_image(pid: int) -> str | None:
    """Read a process image path and fail closed when it is unavailable."""
    try:
        value = psutil.Process(int(pid)).exe()
        if value:
            return os.path.normcase(os.path.abspath(value))
    except (psutil.Error, OSError, ValueError):
        pass
    handle = None
    try:
        access = getattr(win32con, "PROCESS_QUERY_LIMITED_INFORMATION", 0x1000)
        handle = win32api.OpenProcess(access, False, int(pid))
        value = win32process.GetModuleFileNameEx(handle, 0)
        if value:
            return os.path.normcase(os.path.abspath(value))
    except Exception:
        pass
    finally:
        if handle:
            try:
                win32api.CloseHandle(handle)
            except Exception:
                pass
    return None


def target_identity(pid: int, target_exe: str | None, target_name: str) -> dict:
    image = process_image(pid)
    image_name = os.path.basename(image or "")
    matched = bool(image) and image_name.casefold() == target_name.casefold()
    expected = None
    if target_exe:
        expected = os.path.normcase(os.path.abspath(target_exe))
        matched = matched and image == expected
    return {
        "pid": int(pid),
        "image": image,
        "image_name": image_name,
        "target_name": target_name,
        "target_exe": expected,
        "matched": bool(matched),
    }


def enum_top(only_pids: set[int] | None = None) -> list[dict]:
    """Enumerate top-level windows, optionally filtering by verified PID."""
    rows: list[dict] = []

    def cb(hwnd, _):
        try:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid and (only_pids is None or pid in only_pids):
                rows.append(
                    {
                        "hwnd": int(hwnd),
                        "pid": int(pid),
                        "class": win32gui.GetClassName(hwnd),
                        "title": win32gui.GetWindowText(hwnd),
                        "visible": bool(win32gui.IsWindowVisible(hwnd)),
                        "enabled": bool(win32gui.IsWindowEnabled(hwnd)),
                        "rect": list(win32gui.GetWindowRect(hwnd)),
                    }
                )
        except Exception:
            pass

    win32gui.EnumWindows(cb, None)
    return rows


def children(hwnd: int) -> list[dict]:
    rows: list[dict] = []

    def cb(child, _):
        try:
            rows.append(
                {
                    "hwnd": int(child),
                    "id": int(win32gui.GetDlgCtrlID(child)),
                    "class": win32gui.GetClassName(child),
                    "title": win32gui.GetWindowText(child),
                    "visible": bool(win32gui.IsWindowVisible(child)),
                    "enabled": bool(win32gui.IsWindowEnabled(child)),
                    "rect": list(win32gui.GetWindowRect(child)),
                }
            )
        except Exception:
            pass

    try:
        win32gui.EnumChildWindows(hwnd, cb, None)
    except Exception:
        pass
    return rows


def protector_ok_control(parent_hwnd: int) -> dict | None:
    """Find the Enigma warning's custom OK control during creation races."""
    try:
        hwnd = win32gui.FindWindowEx(parent_hwnd, 0, PROTECTOR_WARNING_BUTTON_CLASS, None)
        if hwnd:
            return {
                "hwnd": int(hwnd),
                "id": int(win32gui.GetDlgCtrlID(hwnd)),
                "class": win32gui.GetClassName(hwnd),
                "title": win32gui.GetWindowText(hwnd),
                "visible": bool(win32gui.IsWindowVisible(hwnd)),
                "enabled": bool(win32gui.IsWindowEnabled(hwnd)),
                "rect": list(win32gui.GetWindowRect(hwnd)),
            }
    except Exception:
        pass
    return None


def emit(out, typ: str, **payload) -> None:
    row = {"ts": time.time(), "type": typ, **payload}
    out.write(json.dumps(row, ensure_ascii=False) + "\n")
    out.flush()


def click(out, kind: str, parent: dict, button: dict, clicked: set[int], *, post: bool = False,
          direct_after_post: bool = False, command_after_post: bool = False) -> None:
    hwnd = button["hwnd"]
    if hwnd in clicked:
        return
    clicked.add(hwnd)
    emit(out, "click", action=kind, window=parent, button=button)
    try:
        if post:
            ok = bool(win32gui.PostMessage(hwnd, win32con.BM_CLICK, 0, 0))
            # Some VCL modal forms report a disabled parent while their child
            # button is visibly enabled.  Keep the normal posted path first;
            # when Windows rejects the post, synchronously send BM_CLICK once
            # so the observation run can reach the real handler without
            # changing target memory or persistent state.
            # Keep the asynchronous path exactly as posted.  A false return
            # means the queue did not accept the message; converting that
            # result to synchronous SendMessage can block a VCL modal owner.
            if not ok:
                emit(out, "click_post_rejected", action=kind, hwnd=hwnd)
            elif direct_after_post:
                # A VCL button may accept BM_CLICK in the queue but defer
                # owner notification while the modal parent is disabled.
                try:
                    win32gui.SendMessage(hwnd, win32con.BM_CLICK, 0, 0)
                    emit(out, "click_direct", action=kind, hwnd=hwnd,
                         method="SendMessage")
                except Exception as exc:
                    emit(out, "click_direct_error", action=kind, hwnd=hwnd,
                         error=repr(exc))
            if command_after_post:
                # VCL can ignore a child BM_CLICK while its modal owner is
                # disabled.  Queue the owner notification instead of calling
                # SendMessage synchronously (which would block on MessageBox).
                try:
                    ctrl_id = int(win32gui.GetDlgCtrlID(hwnd)) & 0xffff
                    wparam = (win32con.BN_CLICKED << 16) | ctrl_id
                    win32gui.PostMessage(parent["hwnd"], win32con.WM_COMMAND,
                                         wparam, hwnd)
                    emit(out, "click_command", action=kind,
                         parent_hwnd=parent["hwnd"], button_hwnd=hwnd,
                         control_id=ctrl_id, notification="BN_CLICKED")
                except Exception as exc:
                    emit(out, "click_command_error", action=kind,
                         parent_hwnd=parent.get("hwnd"), button_hwnd=hwnd,
                         error=repr(exc))
        else:
            win32gui.SendMessage(hwnd, win32con.BM_CLICK, 0, 0)
            ok = True
        emit(out, "click_done", action=kind, hwnd=hwnd, posted=post, accepted=ok)
    except Exception as exc:
        emit(out, "click_error", action=kind, hwnd=hwnd, error=repr(exc))


def clipboard_probe(out) -> None:
    """Record only metadata for the Unicode clipboard payload after copy."""
    opened = False
    try:
        win32clipboard.OpenClipboard()
        opened = True
        if not win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
            emit(out, "clipboard_check", available=False)
            return
        value = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
        if not isinstance(value, str):
            value = str(value)
        emit(
            out,
            "clipboard_check",
            available=True,
            chars=len(value),
            sha256=hashlib.sha256(value.encode("utf-16le")).hexdigest(),
            prefix=value[:16],
        )
    except Exception as exc:
        emit(out, "clipboard_check_error", error=repr(exc))
    finally:
        if opened:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass


def visible_text(c: dict) -> str:
    return c.get("title") or ""


def pid_candidates(wins: Iterable[dict], title_hint: str) -> set[int]:
    """Infer the target PID from the agreement/main form; never use consent.exe."""
    pids: set[int] = set()
    for w in wins:
        if w["class"] == "TFormAgreement":
            pids.add(w["pid"])
        elif w["class"] in {"TForm1", "TApplication"} and title_hint in w["title"]:
            pids.add(w["pid"])
    return pids


def verified_pids(
    pids: Iterable[int],
    target_exe: str | None,
    target_name: str,
    out=None,
) -> set[int]:
    """Keep only PIDs whose image is ChessShark (and optional exact path)."""
    result: set[int] = set()
    for raw in sorted({int(x) for x in pids if int(x) > 0}):
        identity = target_identity(raw, target_exe, target_name)
        if out is not None:
            emit(out, "target_identity", **identity)
        if identity["matched"]:
            result.add(raw)
        elif out is not None:
            emit(out, "target_rejected", **identity, reason="image_mismatch_or_unreadable")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=240)
    ap.add_argument("--poll-ms", type=int, default=200)
    ap.add_argument("--log", required=True)
    ap.add_argument("--pid", type=int, action="append", default=[])
    ap.add_argument(
        "--target-exe",
        default=None,
        help="exact ChessShark image path; when set, PID path must match",
    )
    ap.add_argument(
        "--target-name",
        default=DEFAULT_TARGET_NAME,
        help="target image basename (default: ChessShark.exe)",
    )
    ap.add_argument("--title-hint", default="鲨鱼象棋")
    ap.add_argument("--update-action", choices=("ignore", "defer", "none"), default="defer")
    agreement = ap.add_mutually_exclusive_group()
    agreement.add_argument("--accept-agreement", action="store_true", default=True)
    agreement.add_argument("--no-accept-agreement", dest="accept_agreement", action="store_false")
    ap.add_argument("--registration-action", choices=("copy", "show", "none"), default="copy")
    ap.add_argument(
        "--login-action",
        choices=("show", "probe", "none"),
        default="none",
        help=(
            "TFormLogin is a startup-loader form. 'probe' records its hidden/"
            "visible state and child count without calling ShowWindow; 'show' "
            "is retained only for backwards-compatible diagnostics."
        ),
    )
    ap.add_argument("--messagebox-action", choices=("ok", "none"), default="ok")
    ap.add_argument(
        "--registration-direct",
        action="store_true",
        help="after a posted copy click, synchronously retry BM_CLICK once",
    )
    ap.add_argument(
        "--registration-wm-command",
        action="store_true",
        help="after posted copy click, queue WM_COMMAND/BN_CLICKED to the form",
    )
    args = ap.parse_args()

    path = Path(args.log)
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + args.seconds if args.seconds > 0 else None
    target_pids: set[int] = set()
    seen_state: dict[int, tuple] = {}
    clicked: set[int] = set()
    shown: set[int] = set()
    probed_login: set[int] = set()
    copy_pending = False
    with path.open("w", encoding="utf-8") as out:
        emit(
            out,
            "helper_start",
            seconds=args.seconds,
            poll_ms=args.poll_ms,
            update_action=args.update_action,
            accept_agreement=args.accept_agreement,
            registration_action=args.registration_action,
            login_action=args.login_action,
            messagebox_action=args.messagebox_action,
            registration_direct=args.registration_direct,
            registration_wm_command=args.registration_wm_command,
            target_exe=(os.path.normcase(os.path.abspath(args.target_exe)) if args.target_exe else None),
            target_name=args.target_name,
        )
        # Explicit PIDs are checked before any window action.  This is the
        # cold8 guard that excludes consent.exe and unrelated VCL processes.
        if args.pid:
            target_pids.update(verified_pids(args.pid, args.target_exe, args.target_name, out))
            if not target_pids:
                emit(out, "helper_error", error="no_explicit_pid_matches_target_image")
                emit(out, "helper_stop", target_pids=[])
                return 2
        while deadline is None or time.time() < deadline:
            allw = enum_top(target_pids if target_pids else None)
            if not target_pids:
                discovered = pid_candidates(allw, args.title_hint)
                target_pids.update(verified_pids(discovered, args.target_exe, args.target_name, out))
            scoped = [w for w in allw if w["pid"] in target_pids]
            # If spawn created the form before the title was painted, accept a
            # ChessShark VCL form only after image verification and lock that PID.
            if not target_pids:
                fallback = [w["pid"] for w in allw if w["class"] in {"TFormAgreement", "TForm1", "TApplication"}]
                target_pids.update(verified_pids(fallback, args.target_exe, args.target_name, out))
                scoped = [w for w in allw if w["pid"] in target_pids]

            for w in scoped:
                # Actionable controls only occur on these VCL forms/dialogs;
                # skip child-tree walks for unrelated helper windows.
                ch = (children(w["hwnd"])
                      if w["class"] in FORM_CLASSES
                      or w["class"] == MESSAGEBOX_CLASS
                      or w["class"] == PROTECTOR_WARNING_CLASS
                      else [])
                if w["class"] == PROTECTOR_WARNING_CLASS and w["visible"]:
                    if not any(c["class"] == PROTECTOR_WARNING_BUTTON_CLASS for c in ch):
                        fallback = protector_ok_control(w["hwnd"])
                        if fallback is not None:
                            ch.append(fallback)
                state = (
                    w["class"],
                    w["title"],
                    w["visible"],
                    w["enabled"],
                    tuple((c["hwnd"], c["class"], c["title"], c["visible"], c["enabled"]) for c in ch),
                )
                if seen_state.get(w["hwnd"]) != state:
                    seen_state[w["hwnd"]] = state
                    emit(out, "window_state", window=w, children=ch, target_pids=sorted(target_pids))

                if w["class"] == "TFormUpdateTip" and w["visible"] and args.update_action != "none":
                    wanted = "忽略该版本" if args.update_action == "ignore" else "下次再说"
                    for c in ch:
                        if c["class"] == "TButton" and visible_text(c) == wanted:
                            click(out, "update_" + args.update_action, w, c, clicked)

                if (
                    args.accept_agreement
                    and w["class"] == "TFormAgreement"
                    and w["visible"]
                ):
                    for c in ch:
                        if c["class"] == "TButton" and c["visible"] and c["enabled"] and visible_text(c) == "同意":
                            click(out, "agreement", w, c, clicked)

                if w["class"] in {"TFormRegist", "TFormLogin"}:
                    wanted_action = args.registration_action if w["class"] == "TFormRegist" else args.login_action
                    if w["class"] == "TFormLogin" and wanted_action == "probe":
                        # TFormLogin's runtime resource is a startup progress
                        # form (Label1/ProgressBar1/Button1/Timer1), not an
                        # account/key entry dialog.  A probe must preserve
                        # the app's event order; in particular it must not
                        # call ShowWindow on a pre-created hidden form.
                        if w["hwnd"] not in probed_login:
                            probed_login.add(w["hwnd"])
                            emit(
                                out,
                                "form_probe",
                                action="TFormLogin",
                                hwnd=w["hwnd"],
                                window=w,
                                child_count=len(ch),
                                expected_components=["Label1", "ProgressBar1", "Button1", "Timer1"],
                                credential_controls=False,
                            )
                        continue
                    if wanted_action in {"copy", "show"} and not w["visible"] and w["hwnd"] not in shown:
                        shown.add(w["hwnd"])
                        try:
                            win32gui.ShowWindow(w["hwnd"], win32con.SW_SHOWNOACTIVATE)
                            win32gui.UpdateWindow(w["hwnd"])
                            emit(out, "show_form", action=w["class"], hwnd=w["hwnd"], window=w)
                        except Exception as exc:
                            emit(out, "show_form_error", action=w["class"], hwnd=w["hwnd"], window=w, error=repr(exc))
                    # The parent VCL form can remain disabled while its own
                    # controls are enabled during modal-state transitions.
                    # Gate on each button rather than on the parent window.
                    if w["class"] == "TFormRegist" and w["visible"] and args.registration_action == "copy":
                        for c in ch:
                            if c["class"] == "TButton" and c["visible"] and c["enabled"] and "复制" in visible_text(c):
                                # The copy handler opens a modal MessageBoxW.
                                # Post the button message so this watcher can
                                # observe and dismiss that dialog itself.
                                click(
                                    out,
                                    "registration_copy",
                                    w,
                                    c,
                                    clicked,
                                    post=True,
                                    direct_after_post=args.registration_direct,
                                    command_after_post=args.registration_wm_command,
                                )
                                copy_pending = True

                if args.messagebox_action == "ok" and w["class"] == MESSAGEBOX_CLASS and w["visible"]:
                    text = " ".join(visible_text(c) for c in ch)
                    if "机器码" in text or "剪贴板" in text:
                        for c in ch:
                            if c["class"] == "Button" and c["visible"] and c["enabled"]:
                                click(out, "messagebox_ok", w, c, clicked)
                                if copy_pending:
                                    time.sleep(0.05)
                                    clipboard_probe(out)
                                    copy_pending = False
                                break

                # Enigma Protector emits a custom modal ``Virus warning``
                # before the application reaches its VCL startup forms.  It
                # is target-owned and has a single ``&OK`` control; dismiss
                # it through the same reversible BM_CLICK path as the other
                # observed dialogs so an unattended run can proceed.
                if (
                    args.messagebox_action == "ok"
                    and w["class"] == PROTECTOR_WARNING_CLASS
                    and w["visible"]
                ):
                    matched = False
                    for c in ch:
                        if (
                            c["class"] == PROTECTOR_WARNING_BUTTON_CLASS
                            and c["visible"]
                            and c["enabled"]
                            and visible_text(c).strip().lower() in {"&ok", "ok"}
                        ):
                            click(out, "protector_warning_ok", w, c, clicked)
                            matched = True
                            break
                    if not matched:
                        # During the loader's first paint the custom button
                        # can be absent from both EnumChildWindows and
                        # FindWindowEx.  IDOK is the dialog's default command;
                        # queue it once so startup does not wait for a human
                        # click while the child control is materializing.
                        command_key = -int(w["hwnd"])
                        if command_key not in clicked:
                            clicked.add(command_key)
                            try:
                                win32gui.PostMessage(w["hwnd"], win32con.WM_COMMAND, win32con.IDOK, 0)
                                emit(out, "click_command", action="protector_warning_ok",
                                     parent_hwnd=w["hwnd"], notification="IDOK")
                            except Exception as exc:
                                emit(out, "click_command_error", action="protector_warning_ok",
                                     parent_hwnd=w["hwnd"], error=repr(exc))
            # Explicit --pid runs are already image-verified, so a 20 ms
            # floor reduces latency for posted VCL actions without making
            # PID-discovery mode spin on the entire desktop.
            min_interval = 0.02 if args.pid else 0.05
            time.sleep(max(min_interval, args.poll_ms / 1000.0))
        emit(out, "helper_stop", target_pids=sorted(target_pids))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
