"""Operator-facing messages say AutoSecOps, not Vigil (W0.13 review).

The rebrand commits covered the console, emails and the desktop app, but the
banners start.sh / setup_dev.sh / shutdown_all.sh print, the venv check in
scripts/lib.sh, the shipped-default password error, the empty-schema summary
the storage status reports and the restore error still named Vigil.
Comments, identifiers, paths and env names (VIGIL_*, vigil_app, the chart
directory) are not user-visible and stay.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]

SHELL = ("start.sh", "setup_dev.sh", "shutdown_all.sh", "scripts/lib.sh")
# Shell lines that print: echo/printf with a literal containing the old name.
PRINTS = re.compile(r"^\s*(echo|printf)\b.*\bVigil\b")


@pytest.mark.parametrize("path", SHELL)
def test_shell_messages_do_not_name_vigil(path):
    lines = (REPO / path).read_text(encoding="utf-8").splitlines()
    hits = [
        f"{path}:{n}: {ln.strip()}"
        for n, ln in enumerate(lines, 1)
        if PRINTS.search(ln)
    ]
    assert not hits, "\n".join(hits)


@pytest.mark.parametrize(
    "path, message",
    [
        ("core/storage/connection.py", "published default shipped with "),
        ("core/storage/connection.py", "Database has no "),
        ("core/backup/restore.py", "snapshot does not contain one "),
        ("scripts/create_workflow.py", "on finding <id>"),
        ("scripts/generate_sample_data.py", 'Sample Data Generator")'),
    ],
)
def test_python_messages_do_not_name_vigil(path, message):
    text = (REPO / path).read_text(encoding="utf-8")
    at = text.index(message)
    window = text[at : at + 160]
    assert "Vigil" not in window, window


def test_api_startup_logs_do_not_name_vigil_soc():
    """Round 3: the API's startup log lines said "Vigil SOC"."""
    text = (REPO / "services/api/main.py").read_text(encoding="utf-8")
    assert "Vigil SOC" not in text


# --------------------------------------------------------------- W0.38 (G8)
# The surfaces a customer meets before the console: README (also in the
# air-gap docs tarball), Helm metadata and NOTES, the e-mail sender, the login
# panel, the logo and favicon, the support tool's file names and output, and
# SECURITY.md. Upstream credit stays where the licence wants it (NOTICE,
# README "Credits"); internal identifiers stay (chart name `vigil`, VIGIL_*,
# vigil-support.sh, deeptempo_soc, paths of pre-2.0 installs).

UPSTREAM_CREDIT = re.compile(r"based on|upstream|Vigil-SOC|FORK\.md")


def test_readme_is_autosecops_with_upstream_credit_only():
    text = (REPO / "README.md").read_text(encoding="utf-8")
    assert text.startswith("# AutoSecOps\n")
    for gone in (
        "vigilsoc",
        "Discord",
        "Vigil-SOC/vigil.git",
        "Vigil 1.0",
        "helm install vigil ",
    ):
        assert gone not in text, gone
    stray = [
        ln
        for ln in text.splitlines()
        if "Vigil" in ln and not UPSTREAM_CREDIT.search(ln)
    ]
    assert not stray, "\n".join(stray)
    assert "## Credits" in text and "[NOTICE](NOTICE)" in text


def test_helm_metadata_and_notes_say_autosecops():
    import yaml

    chart = yaml.safe_load(
        (REPO / "infra/helm/vigil/Chart.yaml").read_text(encoding="utf-8")
    )
    assert chart["name"] == "vigil"  # kept: renaming it renames every resource
    meta = " ".join(
        str(chart.get(k))
        for k in ("description", "home", "sources", "maintainers", "icon")
    )
    assert "AutoSecOps" in chart["description"]
    assert "vigil" not in meta.lower() and "deeptempo" not in meta.lower(), meta
    notes = (REPO / "infra/helm/vigil/templates/NOTES.txt").read_text(encoding="utf-8")
    assert notes.startswith("AutoSecOps has been installed")
    assert "Vigil" not in notes


@pytest.mark.parametrize(
    "path, pattern",
    [
        ("core/config.py", r'smtp_from: str = "([^"]+)"'),
        ("env.example", r'^SMTP_FROM="([^"]+)"'),
        ("infra/helm/vigil/values.yaml", r'^  SMTP_FROM: "([^"]+)"'),
    ],
)
def test_default_mail_sender_is_not_vigil(path, pattern):
    m = re.search(pattern, (REPO / path).read_text(encoding="utf-8"), re.M)
    assert m and m.group(1) == "noreply@autosecops.local", path


def test_login_panel_has_no_upstream_tagline():
    text = (REPO / "clients/web/src/screens/login/AuthLayout.tsx").read_text(
        encoding="utf-8"
    )
    assert "Vigilant" not in text and "community built" not in text


UPSTREAM_FAVICON = "1d805bacfbd70673a583d9f99e340eb082a5aaa2679f4441b8e4040ab3c22d2c"


def test_logo_and_favicon_are_not_the_vigil_mark():
    import hashlib

    logo = (REPO / "clients/web/src/shared/VigilLogo.tsx").read_text(encoding="utf-8")
    assert "M1201.14 1149.76" not in logo, "the upstream circuit-shield mark is back"
    assert not list((REPO / "clients/web/src").rglob("vigil-*.svg"))
    favicon = (REPO / "clients/web/public/favicon.ico").read_bytes()
    assert hashlib.sha256(favicon).hexdigest() != UPSTREAM_FAVICON


SUPPORT = REPO / "scripts/vigil-support/vigil-support.sh"
# Lines that write what the operator reads: messages, SUMMARY text, skip reasons.
SAYS = re.compile(r"\b(echo|printf|die|skip|collect_cmd|INSTALL_NOTE=)\b")


def test_support_tool_names_and_output_say_autosecops():
    text = SUPPORT.read_text(encoding="utf-8")
    assert "NAME=autosecops-support-$KIND-$VERSION-$STAMP" in text
    assert "printf 'autosecops-support: %s\\n'" in text
    # Paths of installs made before the rename (~/.config/Vigil, ...) are kept.
    stray = [
        ln.strip()
        for ln in text.splitlines()
        if SAYS.search(ln)
        and re.search(r"Vigil(?![/\w])", ln)
        and not ln.lstrip().startswith("#")
    ]
    assert not stray, "\n".join(stray)
    build = (REPO / "scripts/build-support-tarball.sh").read_text(encoding="utf-8")
    assert "DIR=autosecops-support" in build


def test_security_policy_reports_to_us_not_upstream():
    text = (REPO / "SECURITY.md").read_text(encoding="utf-8")
    for gone in (
        "deeptempo.ai",
        "Vigil-SOC/vigil/security",
        "vigilsoc",
        "0.5.x",
        "Computer Fraud",
    ):
        assert gone not in text, gone
    assert (
        "https://github.com/SingularityRD/autosecops2/security/advisories/new" in text
    )
    assert "AutoSecOps 2.x" in text and "## Supported Versions" in text
