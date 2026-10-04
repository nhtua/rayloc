#!/bin/sh
# Install a prebuilt rayloc release binary.
#
#   curl -fsSL https://raw.githubusercontent.com/nhtua/rayloc/main/install.sh | sh
#
# Environment:
#   RAYLOC_VERSION      release to install, e.g. 2026.10.4 (default: latest)
#   RAYLOC_INSTALL_DIR  destination directory (default: $HOME/.local/bin)
#   RAYLOC_REPO         GitHub repository (default: nhtua/rayloc)
#   RAYLOC_RELEASES_URL releases base URL (default: https://github.com/$RAYLOC_REPO/releases)
set -eu

fail() {
    echo "rayloc install: $*" >&2
    exit 1
}

repo="${RAYLOC_REPO:-nhtua/rayloc}"
releases="${RAYLOC_RELEASES_URL:-https://github.com/$repo/releases}"
directory="${RAYLOC_INSTALL_DIR:-$HOME/.local/bin}"
version="${RAYLOC_VERSION:-}"

case "$(uname -s)" in
    Linux) system=unknown-linux-musl ;;
    Darwin) system=apple-darwin ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) machine=x86_64 ;;
    arm64 | aarch64) machine=aarch64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac
target="$machine-$system"

if [ -z "$version" ]; then
    # GitHub redirects releases/latest to releases/tag/v<version>.
    latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$releases/latest") ||
        fail "cannot resolve the latest release of $repo"
    version="${latest##*/}"
fi
version="${version#v}"
case "$version" in
    '' | *[!0-9.]*) fail "invalid release version: $version" ;;
esac

archive="rayloc-$version-$target.tar.gz"
download="$releases/download/v$version"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT INT TERM

curl -fsSL -o "$temporary/$archive" "$download/$archive" ||
    fail "cannot download $archive"
curl -fsSL -o "$temporary/SHA256SUMS" "$download/SHA256SUMS" ||
    fail "cannot download SHA256SUMS"
expected=$(awk -v name="$archive" '$2 == name { print $1 }' "$temporary/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$temporary/$archive" | cut -d ' ' -f 1)
else
    actual=$(shasum -a 256 "$temporary/$archive" | cut -d ' ' -f 1)
fi
[ -n "$expected" ] && [ "$actual" = "$expected" ] ||
    fail "checksum mismatch for $archive"

tar -xzf "$temporary/$archive" -C "$temporary"
mkdir -p "$directory"
# Stage inside the destination so the final rename is atomic.
staged="$directory/.rayloc.$$"
cp "$temporary/rayloc-$version-$target/rayloc" "$staged"
chmod 755 "$staged"
mv -f "$staged" "$directory/rayloc"
echo "installed $("$directory/rayloc" --version) to $directory/rayloc"
case ":$PATH:" in
    *":$directory:"*) ;;
    *) echo "add $directory to PATH, e.g. export PATH=\"$directory:\$PATH\"" ;;
esac
