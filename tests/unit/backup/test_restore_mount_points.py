"""Restoring a directory that has a mount point inside it (W0.26).

On Helm the case evidence claim is mounted at <State Directory>/evidence. The
directory swap used to rename every entry of the State Directory aside, and a
rename of a mount point fails with EBUSY, so the whole restore failed. Mount
points are now swapped in place: their contents move aside inside the mount and
the snapshot's are moved in; an undo puts everything back.

A real mount needs root and a second filesystem, so ``os.path.ismount`` is
patched and a rename of the "mounted" directory raises EBUSY as the kernel does.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from core.backup import restore
from core.backup.create import PRE_RESTORE_PREFIX, STAGE_PREFIX

pytestmark = pytest.mark.unit

STAMP = "20261015T000000Z"


@pytest.fixture
def state(tmp_path, monkeypatch):
    target = tmp_path / "state"
    (target / "evidence" / "CASE-1").mkdir(parents=True)
    (target / "evidence" / "CASE-1" / "old.pdf").write_text("old evidence")
    (target / "secrets.enc").write_text("old secrets")

    staged = target / f"{STAGE_PREFIX}{STAMP}"
    (staged / "evidence" / "CASE-2").mkdir(parents=True)
    (staged / "evidence" / "CASE-2" / "new.pdf").write_text("restored evidence")
    (staged / "secrets.enc").write_text("restored secrets")

    mount = target / "evidence"
    real_ismount = os.path.ismount
    monkeypatch.setattr(
        restore.os.path,
        "ismount",
        lambda p: Path(p) == mount or real_ismount(p),
    )
    real_rename = Path.rename

    def rename(self, dest):
        if self == mount:
            raise OSError(errno.EBUSY, "Device or resource busy", str(self))
        return real_rename(self, dest)

    monkeypatch.setattr(Path, "rename", rename)
    monkeypatch.setattr(restore, "vigil_path", lambda *p: target.joinpath(*p))
    item = restore._Placed("state_directory", staged, target, is_dir=True)
    return target, staged, mount, item


def test_a_mount_point_is_restored_in_place(state):
    target, staged, mount, item = state
    inode = mount.stat().st_ino

    lines = restore._swap_files([item], STAMP)

    assert mount.stat().st_ino == inode  # never renamed
    assert (mount / "CASE-2" / "new.pdf").read_text() == "restored evidence"
    assert not (mount / "CASE-1").exists()
    aside = mount / f"{PRE_RESTORE_PREFIX}{STAMP}"
    assert (aside / "CASE-1" / "old.pdf").read_text() == "old evidence"
    assert (target / "secrets.enc").read_text() == "restored secrets"
    previous = target / f"{PRE_RESTORE_PREFIX}{STAMP}"
    assert (previous / "secrets.enc").read_text() == "old secrets"
    assert not (previous / "evidence").exists()
    assert not staged.exists()
    assert any(
        line.startswith("restored in place state_directory/evidence") for line in lines
    )


def test_a_failed_restore_puts_the_mount_back(state, monkeypatch):
    target, staged, mount, item = state
    boom = restore._Placed(
        "intent", target / "missing", target / "INTENT.md", is_dir=False
    )

    with pytest.raises(Exception):
        restore._swap_files([item, boom], STAMP)

    assert (mount / "CASE-1" / "old.pdf").read_text() == "old evidence"
    assert not (mount / "CASE-2").exists()
    assert not (mount / f"{PRE_RESTORE_PREFIX}{STAMP}").exists()
    assert (target / "secrets.enc").read_text() == "old secrets"
    assert (
        staged / "evidence" / "CASE-2" / "new.pdf"
    ).read_text() == "restored evidence"


def test_a_mount_the_snapshot_lacks_is_left_alone(state, caplog):
    target, staged, mount, item = state
    for path in sorted((staged / "evidence").rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    (staged / "evidence").rmdir()

    restore._swap_files([item], STAMP)

    assert (mount / "CASE-1" / "old.pdf").read_text() == "old evidence"
    assert "mount point the snapshot has nothing for" in caplog.text
