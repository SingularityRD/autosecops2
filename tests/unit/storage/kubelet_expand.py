"""What the kubelet does to a container's ``command``/``args`` before running it.

Port of Kubernetes' ``third_party/forked/golang/expansion/expand.go``:
``$(NAME)`` becomes the value of the container's env var NAME (left as is when
NAME is not defined), ``$$`` becomes ``$``, and every other ``$`` stays. A shell
script in ``command:`` therefore loses half of every ``$$`` (a psql ``DO $$``
block reaches psql as ``DO $``). Tests that run a template's script must run
what the kubelet hands the container, not the YAML text.
"""

from __future__ import annotations

from typing import Mapping


def _read_name(rest: str) -> tuple[str, bool, int]:
    if rest[0] == "$":
        return "$", False, 1
    if rest[0] == "(":
        for i in range(1, len(rest)):
            if rest[i] == ")":
                return rest[1:i], True, i + 1
        return "$(", False, 1
    return "$" + rest[0], False, 1


def kubelet_expand(text: str, env: Mapping[str, str]) -> str:
    out: list[str] = []
    checkpoint = cursor = 0
    while cursor < len(text):
        if text[cursor] == "$" and cursor + 1 < len(text):
            out.append(text[checkpoint:cursor])
            read, is_var, advance = _read_name(text[cursor + 1 :])
            out.append(env.get(read, f"$({read})") if is_var else read)
            cursor += advance
            checkpoint = cursor + 1
        cursor += 1
    out.append(text[checkpoint:])
    return "".join(out)
