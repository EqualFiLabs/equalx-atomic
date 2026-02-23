#!/usr/bin/env bash
set -euo pipefail

# Ubuntu 22.04 Flutter + Android prerequisites installer (idempotent)
# Run as your normal user (script will use sudo for apt).

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
FLUTTER_HOME="${FLUTTER_HOME:-$HOME/development/flutter}"
ANDROID_CMDLINE_TOOLS_URL="${ANDROID_CMDLINE_TOOLS_URL:-https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip}"

echo "==> Installing system packages..."
sudo apt-get update
sudo apt-get install -y \
  curl git unzip xz-utils zip \
  libglu1-mesa \
  openjdk-17-jdk \
  clang cmake ninja-build

echo "==> Installing Android cmdline-tools..."
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

curl -fL "$ANDROID_CMDLINE_TOOLS_URL" -o "$tmpdir/cmdline-tools.zip"
unzip -q -o "$tmpdir/cmdline-tools.zip" -d "$tmpdir"

rm -rf "$ANDROID_SDK_ROOT/cmdline-tools/latest"
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools/latest"

if [ -d "$tmpdir/cmdline-tools" ]; then
  cp -r "$tmpdir/cmdline-tools/"* "$ANDROID_SDK_ROOT/cmdline-tools/latest/"
else
  cp -r "$tmpdir/"* "$ANDROID_SDK_ROOT/cmdline-tools/latest/"
fi

export ANDROID_HOME="$ANDROID_SDK_ROOT"
export PATH="$PATH:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools"

echo "==> Accepting Android licenses + installing platform tools..."
yes | sdkmanager --licenses >/dev/null
sdkmanager --install \
  "platform-tools" \
  "platforms;android-34" \
  "build-tools;34.0.0"

echo "==> Installing Flutter..."
if [ ! -d "$FLUTTER_HOME/.git" ]; then
  git clone https://github.com/flutter/flutter.git -b stable "$FLUTTER_HOME"
else
  git -C "$FLUTTER_HOME" fetch --all --prune
  git -C "$FLUTTER_HOME" checkout stable
  git -C "$FLUTTER_HOME" pull --ff-only
fi

echo "==> Persisting env vars to ~/.bashrc..."
if ! grep -q "FLUTTER_HOME=\"$FLUTTER_HOME\"" "$HOME/.bashrc" 2>/dev/null; then
  cat >> "$HOME/.bashrc" <<EOF

# Flutter + Android SDK
export FLUTTER_HOME="$FLUTTER_HOME"
export ANDROID_SDK_ROOT="$ANDROID_SDK_ROOT"
export ANDROID_HOME="\$ANDROID_SDK_ROOT"
export PATH="\$PATH:\$FLUTTER_HOME/bin:\$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:\$ANDROID_SDK_ROOT/platform-tools"
EOF
fi

export FLUTTER_HOME="$FLUTTER_HOME"
export PATH="$PATH:$FLUTTER_HOME/bin"

echo "==> Final Flutter setup..."
flutter config --android-sdk "$ANDROID_SDK_ROOT"
flutter precache --android
flutter doctor -v

echo "Done. Open a new shell (or run: source ~/.bashrc)."
