#!/bin/sh
set -eu

BUNDLE=${1:?usage: codesign_app.sh <path/to/哈基米.app>}
HELPER="$BUNDLE/Contents/Resources/HajimiHelper"

# A Developer ID identity is what makes the privileged-helper installer able to
# verify code identity: the App checks that the helper it is about to install
# as root carries the same Team ID as itself. Ad-hoc signatures carry no team,
# so those builds are development-only and the installer refuses them unless
# the developer opts in explicitly.
IDENTITY=${HAJIMI_SIGN_IDENTITY:-}

if [ -n "$IDENTITY" ]; then
    echo "Signing with identity: $IDENTITY"
    /usr/bin/codesign --force --options runtime --timestamp \
        --sign "$IDENTITY" "$HELPER"
    /usr/bin/codesign --force --options runtime --timestamp \
        --sign "$IDENTITY" "$BUNDLE"
    TEAM=$(/usr/bin/codesign -dv --verbose=4 "$BUNDLE" 2>&1 \
        | /usr/bin/awk -F= '/^TeamIdentifier=/ {print $2}')
    if [ -z "$TEAM" ] || [ "$TEAM" = "not set" ]; then
        echo "Signed bundle carries no Team ID; the helper installer cannot verify identity" >&2
        exit 1
    fi
    echo "Team ID: $TEAM"
else
    echo "HAJIMI_SIGN_IDENTITY not set — falling back to an ad-hoc signature."
    echo "This build is development-only: installing the privileged helper will"
    echo "require HAJIMI_ALLOW_ADHOC_HELPER=1 because ad-hoc code identity cannot"
    echo "be verified."
    /usr/bin/codesign --force --sign - "$HELPER"
    /usr/bin/codesign --force --deep --sign - "$BUNDLE"
fi

/usr/bin/codesign --verify --deep --strict "$BUNDLE"
