#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
code_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
skill_source="$code_root/skills/app-workbench"
skill_home="${CODEX_HOME:-$HOME/.codex}/skills"
skill_target="$skill_home/app-workbench"
mkdir -p "$skill_home"
if [ -L "$skill_target" ] && [ "$(readlink "$skill_target")" = "$skill_source" ]; then
  printf 'AppWorkbench skill already installed: %s\n' "$skill_target"
elif [ -e "$skill_target" ] || [ -L "$skill_target" ]; then
  printf 'Refusing to replace existing skill: %s\n' "$skill_target" >&2
  exit 1
else
  ln -s "$skill_source" "$skill_target"
  printf 'AppWorkbench skill installed: %s\n' "$skill_target"
fi
