#!/bin/bash
set -euo pipefail
[[ $# == 2 ]] || { echo "Usage: build-macos.sh arm64|x86_64 OUTPUT_DIR" >&2; exit 2; }
arch=$1
case "$arch" in arm64|x86_64) ;; *) exit 2 ;; esac
[[ "$(uname -s)" == Darwin && "$(uname -m)" == "$arch" ]]
python -c 'import platform,sys; assert platform.machine() == sys.argv[1]' "$arch"
tool=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
scratch=$(mktemp -d)
app='KatoVPN Router Control'
python -m PyInstaller --noconfirm --clean --onedir --windowed --noupx \
    --name "$app" --osx-bundle-identifier app.katovpn.routercontrol \
    --target-architecture "$arch" --icon "$tool/web/logo.png" \
    --paths "$tool" --add-data "$tool/web:web" --add-data "$tool/profile:profile" \
    --distpath "$scratch/dist" --workpath "$scratch/work" --specpath "$scratch/spec" "$tool/app.py"
bundle="$scratch/dist/$app.app"
exe="$bundle/Contents/MacOS/$app"
[[ "$(lipo -archs "$exe")" == "$arch" ]]
codesign --verify --deep --strict "$bundle"
"$exe" --smoke-test --no-browser
file="KatoVPN-Router-Control-v0.4.3-preview-macos-$arch.zip"
ditto -c -k --keepParent "$bundle" "$out/$file"
cd "$out"
shasum -a 256 "$file" > "$file.sha256"
shasum -a 256 -c "$file.sha256"
dmg="KatoVPN-Router-Control-v0.4.3-preview-macos-$arch.dmg"
hdiutil create -srcfolder "$bundle" -volname "$app" -format UDZO "$out/$dmg"
hdiutil verify "$out/$dmg"
shasum -a 256 "$dmg" > "$dmg.sha256"
shasum -a 256 -c "$dmg.sha256"
