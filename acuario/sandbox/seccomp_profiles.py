"""Seccomp profiles for scanner sandbox containers.

Two profiles: HUNTER (default for all hunt containers) and EXPLOIT (permissive
for exploit-development containers that need broader syscall access). Both
block dangerous host-escape syscalls like mount, pivot_root, reboot, kexec_load.
"""

from __future__ import annotations

import json
from pathlib import Path

_BLOCKED_SYSCALLS = [
    "mount",
    "umount2",
    "pivot_root",
    "reboot",
    "sethostname",
    "setdomainname",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
]

_EXTRA_HUNTER_BLOCKED = [
    "unshare",
    "setns",
]

HUNTER_SECCOMP: dict = {
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
        {
            "names": _BLOCKED_SYSCALLS + _EXTRA_HUNTER_BLOCKED,
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
        },
    ],
}

EXPLOIT_SECCOMP: dict = {
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
        {
            "names": _BLOCKED_SYSCALLS,
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
        },
    ],
}

# networking syscalls. Analyzers never need to open sockets - the sandbox
# already runs with network_mode="none", but blocking the syscalls themselves
# is defense-in-depth (it also forecloses AF_UNIX abuse against host sockets).
# NOT applied by default: a deep analyzer may legitimately run a target server
# on loopback to confirm a bug, so this lives in the opt-in strict profile only
# and is kept OUT of the exploit profile (the live-app harness needs sockets
# for its loopback probes).
_NETWORK_SYSCALLS = [
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
]

# Strict analyzer profile: the hunter denylist plus networking. Selected via
# AnalyzerSandbox(strict_seccomp=True) / the `--strict-sandbox` CLI flag.
HUNTER_STRICT_SECCOMP: dict = {
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
        {
            "names": _BLOCKED_SYSCALLS + _EXTRA_HUNTER_BLOCKED + _NETWORK_SYSCALLS,
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
        },
    ],
}


def get_seccomp_profile(mode: str = "analyzer") -> dict:
    if mode == "exploit":
        return EXPLOIT_SECCOMP
    if mode == "analyzer-strict":
        return HUNTER_STRICT_SECCOMP
    return HUNTER_SECCOMP


def write_seccomp_profile(mode: str, path: Path) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    profile = get_seccomp_profile(mode)
    path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return str(path)
