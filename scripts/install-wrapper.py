#!/usr/bin/env python3
"""Install the fail-closed LYTA Shield function into a shell profile."""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

START = "# LYTA Shield — hermes wrapper (auto-installed)"
END = "# END LYTA Shield — hermes wrapper"


def shell_double_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: install-wrapper.py <shell-profile> <shield-dir> <hermes-bin>", file=sys.stderr)
        return 2
    profile = Path(sys.argv[1]).expanduser()
    shield_dir = Path(sys.argv[2]).resolve(strict=True)
    hermes_bin = Path(sys.argv[3]).resolve(strict=True)
    wrapper = shield_dir / "integrations" / "hermes-wrapper.sh"
    if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
        print(f"wrapper is missing or not executable: {wrapper}", file=sys.stderr)
        return 1
    if not hermes_bin.is_file() or not os.access(hermes_bin, os.X_OK):
        print(f"Hermes executable is invalid: {hermes_bin}", file=sys.stderr)
        return 1

    shield_text = shell_double_quote(str(shield_dir))
    hermes_text = shell_double_quote(str(hermes_bin))
    block = f'''{START}
: "${{LYTA_SHIELD_DIR:={shield_text}}}"
: "${{LYTA_HERMES_BIN:={hermes_text}}}"
LYTA_SHIELD_WRAPPER="${{LYTA_SHIELD_DIR}}/integrations/hermes-wrapper.sh"
LYTA_SHIELD_STRICT="${{LYTA_SHIELD_STRICT:-1}}"
hermes() {{
  if [[ -x "$LYTA_SHIELD_WRAPPER" && -x "$LYTA_HERMES_BIN" ]]; then
    "$LYTA_SHIELD_WRAPPER" "$LYTA_HERMES_BIN" "$@"
  elif [[ "$LYTA_SHIELD_STRICT" == "1" ]]; then
    echo "LYTA Shield guard or Hermes executable is unavailable." >&2
    return 1
  else
    "$LYTA_HERMES_BIN" "$@"
  fi
}}
{END}'''

    text = profile.read_text(encoding="utf-8") if profile.exists() else ""
    text = re.sub(
        rf"\n?{re.escape(START)}[\s\S]*?{re.escape(END)}\n?",
        "\n",
        text,
    )
    text = re.sub(r"\n?hermes\s*\(\)\s*\{[\s\S]*?\n\}", "\n", text)
    output = text.rstrip() + "\n\n" + block + "\n"
    profile.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{profile.name}.", dir=profile.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(output)
            handle.flush()
            os.fsync(handle.fileno())
        if profile.exists():
            os.chmod(temporary, profile.stat().st_mode & 0o777)
        else:
            os.chmod(temporary, 0o600)
        os.replace(temporary, profile)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"LYTA Shield wrapper installed in {profile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
