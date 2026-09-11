#!/usr/bin/env bash
# Invoked explicitly by install.sh --system. Does not upgrade existing packages.
set -euo pipefail
if [[ ! -r /etc/os-release ]]; then
  echo 'System package automation requires Debian, Ubuntu, or Kali.' >&2
  exit 1
fi
source /etc/os-release
case " $ID ${ID_LIKE:-} " in
  *debian*|*ubuntu*|*kali*) ;;
  *) echo 'Unsupported distribution. Install nmap, Chromium, Python 3.11–3.13 and venv support manually.' >&2; exit 1 ;;
esac
packages=(ca-certificates python3-venv nmap chromium)
# Ubuntu provides Chromium through snap; use its distribution package name.
if [[ "$ID" == ubuntu ]]; then packages=(ca-certificates python3-venv nmap chromium-browser); fi
# BBOT checks these core dependencies even when module installation is disabled.
packages+=(gcc make libssl-dev openssl p7zip-full unzip curl git debianutils tar xz-utils)
missing=()
for package in "${packages[@]}"; do
  if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" != 'install ok installed' ]]; then
    missing+=("$package")
  fi
done
if (( ${#missing[@]} == 0 )); then
  echo 'System packages already installed.'
  exit 0
fi
elevate=()
if (( EUID != 0 )); then elevate=(sudo); fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
distro="$ID"
if [[ "$distro" != kali && "$distro" != ubuntu && "$distro" != debian ]]; then distro=debian; fi
apt_workspace="$(mktemp -d /tmp/vandal-apt.XXXXXXXX)"
cleanup() {
  # APT creates root-owned index files; clean them through the same privilege path.
  "${elevate[@]}" rm -rf -- "$apt_workspace"
}
trap cleanup EXIT
chmod 755 "$apt_workspace"
mkdir "$apt_workspace/sources" "$apt_workspace/lists"
"${VANDAL_PYTHON:-python3}" "$script_dir/apt_sources.py" "$distro" "$apt_workspace/sources"
apt_options=(
  -o "Dir::Etc::sourcelist=-"
  -o "Dir::Etc::sourceparts=$apt_workspace/sources"
  -o "Dir::State::lists=$apt_workspace/lists"
  -o "APT::Update::Error-Mode=any"
)
echo 'Using configured distribution sources for vandal dependencies (third-party sources excluded).'
"${elevate[@]}" apt-get "${apt_options[@]}" update
"${elevate[@]}" apt-get "${apt_options[@]}" install -y --no-install-recommends "${missing[@]}"
