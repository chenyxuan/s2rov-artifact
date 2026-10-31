#!/usr/bin/env bash
set -euo pipefail

phase7_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendor_root="${phase7_root}/vendor"
mkdir -p "${vendor_root}"

fetch_at_commit() {
  local name="$1"
  local url="$2"
  local commit="$3"
  local destination="${vendor_root}/${name}"

  if [[ ! -d "${destination}/.git" ]]; then
    if [[ -e "${destination}" ]]; then
      echo "refusing to replace non-Git path: ${destination}" >&2
      return 1
    fi
    git clone "${url}" "${destination}"
  fi

  if [[ -n "$(git -C "${destination}" status --porcelain --untracked-files=no)" ]]; then
    echo "refusing to move a checkout with tracked changes: ${destination}" >&2
    return 1
  fi
  if ! git -C "${destination}" cat-file -e "${commit}^{commit}" 2>/dev/null; then
    git -C "${destination}" fetch --depth=1 origin "${commit}"
  fi
  git -C "${destination}" checkout --detach "${commit}"
  printf '%s\t%s\n' "${name}" "$(git -C "${destination}" rev-parse HEAD)"
}

fetch_at_commit \
  bgpy \
  https://github.com/jfuruness/bgpy_pkg.git \
  c3b1be48148e8c246a60b9dec6513b688a4736a5

fetch_at_commit \
  internetsim \
  https://github.com/internetsys/InternetSim.git \
  a96b15716f579658b9d745c8abe1805dd869e375
