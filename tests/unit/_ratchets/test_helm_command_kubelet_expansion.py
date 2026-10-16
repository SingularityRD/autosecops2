"""Shell in a chart's ``command:``/``args:`` must survive kubelet expansion (W0.39).

The kubelet rewrites a container's command and args before running them:
``$$`` becomes ``$`` and ``$(NAME)`` becomes the value of the container's env
var NAME. A script that needs two dollars (a psql ``DO $$`` block) or names an
env var as ``$(NAME)`` means something else in the pod than in the YAML; the
db-init Job's ``DO $$`` reached psql as ``DO $`` and failed on every install.
Env values (``value: "$(POD_IP):..."``) are meant to be expanded and are not
checked.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.unit.storage.kubelet_expand import kubelet_expand

pytestmark = pytest.mark.unit

TEMPLATES = Path(__file__).resolve().parents[3] / "infra" / "helm" / "vigil" / "templates"
ENV_NAME = re.compile(r"^\s*- name: ([A-Z_][A-Z0-9_]*)\s*$", re.MULTILINE)


def _offending_lines(text: str) -> list[str]:
    names = {name: f"<{name}>" for name in ENV_NAME.findall(text)}
    bad = []
    for no, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith(("value:", "- name:")):
            continue
        if kubelet_expand(line, names) != line:
            bad.append(f"{no}: {line.strip()}")
    return bad


@pytest.mark.parametrize("template", sorted(p.name for p in TEMPLATES.glob("*.yaml")))
def test_template_shell_is_unchanged_by_the_kubelet(template):
    bad = _offending_lines((TEMPLATES / template).read_text(encoding="utf-8"))
    assert not bad, (
        f"{template}: the kubelet rewrites these lines ($$ -> $, $(ENV) -> value); "
        f"use a named dollar quote ($w$) or a shell $VAR: {bad}"
    )


def test_the_check_catches_a_double_dollar_and_an_env_reference():
    text = "env:\n  - name: PGUSER\ncommand:\n  - |\n    psql -c 'DO $$ BEGIN END $$'\n    echo $(PGUSER)\n"
    assert len(_offending_lines(text)) == 2
    assert not _offending_lines("command:\n  - |\n    x=$(seq 1 3); y=$((x + 1)); echo $PGUSER $w$\n")
