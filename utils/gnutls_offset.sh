#!/usr/bin/env bash
# Generate offsets from real GnuTLS source on a supported Linux host.
set -euo pipefail

[[ "$(uname -s)" == Linux ]] || { echo 'Offset generation requires Linux' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) minimum_kernel=4.18 ;;
  aarch64|arm64) minimum_kernel=5.5 ;;
  loongarch64|loong64) minimum_kernel=6.6 ;;
  *) echo 'Unsupported offset-generation architecture' >&2; exit 1 ;;
esac
kernel=$(uname -r | cut -d- -f1)
[[ "$(printf '%s\n%s\n' "$minimum_kernel" "$kernel" | sort -V | head -n 1)" == "$minimum_kernel" ]] || {
  echo "Kernel $kernel is too old; require $minimum_kernel" >&2; exit 1;
}
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output_dir=${GNUTLS_OUTPUT_DIR:-$project_root/kern}
compiler=${CC:-clang}
command -v "$compiler" >/dev/null
versions=("$@")
if ((${#versions[@]} == 0)); then
  # Preserve the supported generation range: 3.8.{0 ~ 13}.
  for patch in $(seq 0 13); do versions+=("3.8.$patch"); done
fi
for version in "${versions[@]}"; do
  [[ "$version" =~ ^3[.]8[.]([0-9]|1[0-3])$ ]] || {
    echo "Unsupported generation version: $version (use 3.8.0 through 3.8.13)" >&2; exit 1;
  }
done
if [[ -n "${GNUTLS_SOURCE_DIR:-}" && ${#versions[@]} != 1 ]]; then
  echo 'GNUTLS_SOURCE_DIR requires exactly one version argument' >&2; exit 1
fi
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/ecapture-gnutls-offset.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

for version in "${versions[@]}"; do
  suffix=${version//./_}
  destination="$output_dir/gnutls_${suffix}_kern.c"
  if [[ -e "$destination" ]]; then
    echo "Skip existing $destination; use a separate GNUTLS_OUTPUT_DIR to compare layouts"
    continue
  fi
  if [[ -n "${GNUTLS_SOURCE_DIR:-}" ]]; then
    # Read-only input: configure this source separately with the library's
    # real build options, including downstream patches when applicable.
    source_dir=$(cd "$GNUTLS_SOURCE_DIR" && pwd)
    source_id=${GNUTLS_SOURCE_ID:?Set GNUTLS_SOURCE_ID to the source commit or release archive SHA-256}
  else
    source_dir="$work/gnutls-$version"
    git clone --depth 1 --branch "$version" https://github.com/gnutls/gnutls.git "$source_dir"
    source_id=$(git -C "$source_dir" rev-parse HEAD)
    (
      cd "$source_dir"
      ./bootstrap --skip-po --force --no-bootstrap-sync
      ./configure --without-p11-kit --without-brotli --without-zstd --without-zlib \
        --without-tpm --disable-doc --disable-tests
    )
  fi
  [[ "$source_id" =~ ^[[:xdigit:]]{40}([[:xdigit:]]{24})?$ ]] || {
    echo 'Source identity must be a full Git commit or SHA-256 digest' >&2; exit 1;
  }
  test -f "$source_dir/config.h"
  grep -Fxq "#define PACKAGE_VERSION \"$version\"" "$source_dir/config.h" || {
    echo "Configured source does not match requested version $version" >&2; exit 1;
  }
  "$compiler" -I "$source_dir/gnulib/lib" -I "$source_dir/gl" -I "$source_dir/lib" \
    -I "$source_dir/lib/includes" -I "$source_dir" \
    "$project_root/utils/gnutls_offset.c" -o "$work/offset"
  config_hash=$(sha256sum "$source_dir/config.h" | cut -d' ' -f1)
  {
    printf '#ifndef ECAPTURE_GNUTLS_%s_KERN_H\n#define ECAPTURE_GNUTLS_%s_KERN_H\n\n' "$suffix" "$suffix"
    printf '// GnuTLS %s; source %s\n' "$version" "$source_id"
    printf '// config.h SHA-256: %s\n\n' "$config_hash"
    "$work/offset"
    printf '\n#include "gnutls.h"\n#include "gnutls_masterkey.h"\n\n#endif\n'
  } > "$work/result.c"
  # Configure and compile must succeed before publishing an output.
  cp "$work/result.c" "$destination"
  echo "Generated $destination"
done
