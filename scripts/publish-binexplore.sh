#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROJECT_PATH="$REPO_ROOT/src/RearEnd/BinExplore/B2R2.RearEnd.BinExplore.fsproj"
TEMPLATE_PATH="$REPO_ROOT/src/RearEnd/BinExplore/Packaging/macOS/Info.plist.template"
ICON_PATH="$REPO_ROOT/src/RearEnd/BinExplore/Assets/b2r2.icns"
VERSION_PATH="$REPO_ROOT/Directory.Build.props"

APP_NAME="BinExplore"
EXECUTABLE_NAME="$(basename "${PROJECT_PATH%.fsproj}")"
WINDOWS_EXECUTABLE_NAME="${EXECUTABLE_NAME}.exe"
ICON_FILE="$(basename "$ICON_PATH")"
CONFIGURATION="${CONFIGURATION:-Release}"
BUNDLE_ID="${BUNDLE_ID:-org.b2r2.binexplore}"
NO_RESTORE="${NO_RESTORE:-false}"
PUBLISH_ARCHIVES="${PUBLISH_ARCHIVES:-true}"
OUTPUT_ROOT="$REPO_ROOT/artifacts/binexplore"
SUPPORTED_RIDS=(
  osx-arm64
  osx-x64
  linux-x64
  linux-arm64
  win-x64
  win-arm64
)
ALL_RIDS=(
  osx-arm64
  osx-x64
  linux-x64
  linux-arm64
  win-x64
  win-arm64
)

usage() {
  cat <<EOF >&2
Usage: $(basename "$0") [all|RID...]

Examples:
  $(basename "$0")
  $(basename "$0") osx-arm64 linux-x64 win-x64
  NO_RESTORE=true $(basename "$0") all
EOF
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Required file not found: $path" >&2
    exit 1
  fi
}

has_value() {
  local value="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$value" ]]; then
      return 0
    fi
  done
  return 1
}

read_version() {
  local version
  version="$(sed -n 's:.*<VersionPrefix>\(.*\)</VersionPrefix>.*:\1:p' "$VERSION_PATH" | head -n 1)"
  if [[ -z "$version" ]]; then
    echo "0.0.0"
  else
    echo "$version"
  fi
}

detect_default_rid() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os:$arch" in
    Darwin:arm64) echo "osx-arm64" ;;
    Darwin:x86_64) echo "osx-x64" ;;
    Linux:arm64|Linux:aarch64) echo "linux-arm64" ;;
    Linux:x86_64) echo "linux-x64" ;;
    MINGW*:x86_64|MSYS*:x86_64|CYGWIN*:x86_64) echo "win-x64" ;;
    *) echo "osx-arm64" ;;
  esac
}

publish_project() {
  local rid="$1"
  local publish_dir="$OUTPUT_ROOT/publish/$rid"
  local publish_args=(
    "$PROJECT_PATH"
    -c "$CONFIGURATION"
    -r "$rid"
    -p:UseAppHost=true
    --self-contained false
    -o "$publish_dir"
  )

  if [[ "$NO_RESTORE" == "true" ]]; then
    publish_args+=(--no-restore)
  fi

  dotnet publish "${publish_args[@]}"
}

write_macos_plist() {
  local plist_path="$1"
  sed \
    -e "s|__APP_NAME__|$APP_NAME|g" \
    -e "s|__EXECUTABLE_NAME__|$EXECUTABLE_NAME|g" \
    -e "s|__ICON_FILE__|$ICON_FILE|g" \
    -e "s|__BUNDLE_IDENTIFIER__|$BUNDLE_ID|g" \
    -e "s|__APP_VERSION__|$APP_VERSION|g" \
    "$TEMPLATE_PATH" > "$plist_path"
}

package_macos() {
  local rid="$1"
  local publish_dir="$OUTPUT_ROOT/publish/$rid"
  local package_root="$OUTPUT_ROOT/$rid"
  local app_dir="$package_root/$APP_NAME.app"
  local contents_dir="$app_dir/Contents"
  local macos_dir="$contents_dir/MacOS"
  local resources_dir="$contents_dir/Resources"
  local archive_path="$package_root/$APP_NAME-$rid.zip"

  if [[ ! -f "$publish_dir/$EXECUTABLE_NAME" ]]; then
    echo "Published executable not found: $publish_dir/$EXECUTABLE_NAME" >&2
    exit 1
  fi

  rm -rf "$package_root"
  mkdir -p "$macos_dir" "$resources_dir"

  cp -R "$publish_dir"/. "$macos_dir"/
  cp "$ICON_PATH" "$resources_dir/$ICON_FILE"
  write_macos_plist "$contents_dir/Info.plist"
  chmod +x "$macos_dir/$EXECUTABLE_NAME"

  if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$app_dir"
  fi

  if [[ "$PUBLISH_ARCHIVES" == "true" ]] && command -v ditto >/dev/null 2>&1; then
    rm -f "$archive_path"
    ditto -c -k --keepParent "$app_dir" "$archive_path"
  fi

  echo "Created $app_dir"
}

package_linux() {
  local rid="$1"
  local publish_dir="$OUTPUT_ROOT/publish/$rid"
  local package_root="$OUTPUT_ROOT/$rid"
  local dist_dir="$package_root/$APP_NAME"
  local archive_path="$package_root/$APP_NAME-$rid.tar.gz"

  if [[ ! -f "$publish_dir/$EXECUTABLE_NAME" ]]; then
    echo "Published executable not found: $publish_dir/$EXECUTABLE_NAME" >&2
    exit 1
  fi

  rm -rf "$package_root"
  mkdir -p "$dist_dir"
  cp -R "$publish_dir"/. "$dist_dir"/
  chmod +x "$dist_dir/$EXECUTABLE_NAME"

  if [[ "$PUBLISH_ARCHIVES" == "true" ]]; then
    rm -f "$archive_path"
    tar -C "$package_root" -czf "$archive_path" "$APP_NAME"
  fi

  echo "Created $dist_dir"
}

package_windows() {
  local rid="$1"
  local publish_dir="$OUTPUT_ROOT/publish/$rid"
  local package_root="$OUTPUT_ROOT/$rid"
  local dist_dir="$package_root/$APP_NAME"
  local archive_path="$package_root/$APP_NAME-$rid.zip"

  if [[ ! -f "$publish_dir/$WINDOWS_EXECUTABLE_NAME" ]]; then
    echo "Published executable not found: $publish_dir/$WINDOWS_EXECUTABLE_NAME" >&2
    exit 1
  fi

  rm -rf "$package_root"
  mkdir -p "$dist_dir"
  cp -R "$publish_dir"/. "$dist_dir"/

  if [[ "$PUBLISH_ARCHIVES" == "true" ]]; then
    rm -f "$archive_path"
    (
      cd "$package_root"
      zip -qr "$archive_path" "$APP_NAME"
    )
  fi

  echo "Created $dist_dir"
}

package_rid() {
  local rid="$1"
  case "$rid" in
    osx-*)
      package_macos "$rid"
      ;;
    linux-*)
      package_linux "$rid"
      ;;
    win-*)
      package_windows "$rid"
      ;;
    *)
      echo "Unsupported RID: $rid" >&2
      exit 1
      ;;
  esac
}

require_file "$PROJECT_PATH"
require_file "$VERSION_PATH"
require_file "$TEMPLATE_PATH"
require_file "$ICON_PATH"

APP_VERSION="$(read_version)"

target_rids=()
if [[ $# -eq 0 ]]; then
  target_rids=("$(detect_default_rid)")
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      all)
        target_rids=("${ALL_RIDS[@]}")
        shift
        ;;
      -*)
        usage
        exit 1
        ;;
      *)
        if ! has_value "$1" "${SUPPORTED_RIDS[@]}"; then
          echo "Unsupported RID: $1" >&2
          usage
          exit 1
        fi
        target_rids+=("$1")
        shift
        ;;
    esac
  done
fi

for rid in "${target_rids[@]}"; do
  publish_project "$rid"
  package_rid "$rid"
done
