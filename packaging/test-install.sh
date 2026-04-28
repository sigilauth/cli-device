#!/usr/bin/env bash
# Test all distro packages by installing in clean containers + smoke test
set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

declare -A DISTROS=(
  [ubuntu]="ubuntu:24.04"
  [debian]="debian:bookworm"
  [fedora]="fedora:40"
  [rocky]="rockylinux:9"
  [alpine]="alpine:3.19"
  [arch]="archlinux:latest"
)

RESULTS_FILE="packaging/test-results.md"
FAILED=0
PASSED=0

# Clear previous results
echo "# Package Installation Test Results" > "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "| Distro | Image | Package | Version | Completions | Man Page | SystemD | Status |" >> "$RESULTS_FILE"
echo "|--------|-------|---------|---------|-------------|----------|---------|--------|" >> "$RESULTS_FILE"

for distro in ubuntu debian fedora rocky alpine arch; do
  image="${DISTROS[$distro]}"
  echo -e "${YELLOW}=== Testing $distro ($image) ===${NC}"

  case $distro in
    ubuntu|debian)
      PKG_FILE=$(ls dist/sigil-device_*.deb 2>/dev/null | head -1)
      if [ -z "$PKG_FILE" ]; then
        echo -e "${RED}✗ No .deb package found${NC}"
        echo "| $distro | $image | .deb | N/A | N/A | N/A | N/A | ❌ No package |" >> "$RESULTS_FILE"
        ((FAILED++))
        continue
      fi

      TEST_OUTPUT=$(docker run --rm -v $(pwd)/dist:/pkg $image sh -c '
        rm -f /etc/dpkg/dpkg.cfg.d/excludes  # Remove man page excludes from minimal containers
        apt update -qq 2>&1 >/dev/null || exit 1
        apt install -y /pkg/sigil-device_*.deb 2>&1 >/dev/null || exit 1
        VERSION=$(sigil-device --version 2>&1) || exit 1
        [ -f /usr/share/bash-completion/completions/sigil-device ] || exit 2
        [ -f /usr/share/zsh/site-functions/_sigil-device ] || exit 2
        [ -f /usr/share/fish/vendor_completions.d/sigil-device.fish ] || exit 2
        [ -f /usr/share/man/man1/sigil-device.1 ] || exit 3
        [ -f /usr/lib/systemd/user/sigil-device.service ] || exit 4
        echo "$VERSION|OK|OK|OK"
      ' 2>&1)
      ;;

    fedora|rocky)
      PKG_FILE=$(ls dist/sigil-device-*.rpm 2>/dev/null | head -1)
      if [ -z "$PKG_FILE" ]; then
        echo -e "${RED}✗ No .rpm package found${NC}"
        echo "| $distro | $image | .rpm | N/A | N/A | N/A | N/A | ❌ No package |" >> "$RESULTS_FILE"
        ((FAILED++))
        continue
      fi

      TEST_OUTPUT=$(docker run --rm -v $(pwd)/dist:/pkg $image sh -c '
        dnf install -y /pkg/sigil-device-*.rpm 2>&1 >/dev/null || exit 1
        VERSION=$(sigil-device --version 2>&1) || exit 1
        [ -f /usr/share/bash-completion/completions/sigil-device ] || exit 2
        [ -f /usr/share/zsh/site-functions/_sigil-device ] || exit 2
        [ -f /usr/share/fish/vendor_completions.d/sigil-device.fish ] || exit 2
        [ -f /usr/share/man/man1/sigil-device.1 ] || exit 3
        [ -f /usr/lib/systemd/user/sigil-device.service ] || exit 4
        echo "$VERSION|OK|OK|OK"
      ' 2>&1)
      ;;

    alpine)
      PKG_FILE=$(ls dist/sigil-device_*.apk 2>/dev/null | head -1)
      if [ -z "$PKG_FILE" ]; then
        echo -e "${RED}✗ No .apk package found${NC}"
        echo "| $distro | $image | .apk | N/A | N/A | N/A | N/A | ❌ No package |" >> "$RESULTS_FILE"
        ((FAILED++))
        continue
      fi

      TEST_OUTPUT=$(docker run --rm -v $(pwd)/dist:/pkg $image sh -c '
        apk add --allow-untrusted /pkg/sigil-device_*.apk 2>&1 >/dev/null || exit 1
        VERSION=$(sigil-device --version 2>&1) || exit 1
        [ -f /usr/share/bash-completion/completions/sigil-device ] || exit 2
        [ -f /usr/share/zsh/site-functions/_sigil-device ] || exit 2
        [ -f /usr/share/fish/vendor_completions.d/sigil-device.fish ] || exit 2
        [ -f /usr/share/man/man1/sigil-device.1 ] || exit 3
        [ -f /usr/lib/systemd/user/sigil-device.service ] || exit 4
        echo "$VERSION|OK|OK|OK"
      ' 2>&1)
      ;;

    arch)
      PKG_FILE=$(ls dist/*.pkg.tar.zst 2>/dev/null | head -1)
      if [ -z "$PKG_FILE" ]; then
        echo -e "${RED}✗ No .pkg.tar.zst package found${NC}"
        echo "| $distro | $image | .pkg.tar.zst | N/A | N/A | N/A | N/A | ❌ No package |" >> "$RESULTS_FILE"
        ((FAILED++))
        continue
      fi

      TEST_OUTPUT=$(docker run --rm -v $(pwd)/dist:/pkg $image sh -c '
        sed -i "/NoExtract.*man/d" /etc/pacman.conf  # Remove man page excludes from minimal containers
        pacman -Sy --noconfirm 2>&1 >/dev/null || exit 1
        pacman -U --noconfirm /pkg/*.pkg.tar.zst 2>&1 >/dev/null || exit 1
        VERSION=$(sigil-device --version 2>&1) || exit 1
        [ -f /usr/share/bash-completion/completions/sigil-device ] || exit 2
        [ -f /usr/share/zsh/site-functions/_sigil-device ] || exit 2
        [ -f /usr/share/fish/vendor_completions.d/sigil-device.fish ] || exit 2
        [ -f /usr/share/man/man1/sigil-device.1 ] || exit 3
        [ -f /usr/lib/systemd/user/sigil-device.service ] || exit 4
        echo "$VERSION|OK|OK|OK"
      ' 2>&1)
      ;;
  esac

  EXIT_CODE=$?

  if [ $EXIT_CODE -eq 0 ]; then
    VERSION=$(echo "$TEST_OUTPUT" | tail -1 | cut -d'|' -f1)
    COMPLETIONS=$(echo "$TEST_OUTPUT" | tail -1 | cut -d'|' -f2)
    MANPAGE=$(echo "$TEST_OUTPUT" | tail -1 | cut -d'|' -f3)
    SYSTEMD=$(echo "$TEST_OUTPUT" | tail -1 | cut -d'|' -f4)
    echo -e "${GREEN}✓ $distro: $VERSION${NC}"
    echo "| $distro | $image | ${PKG_FILE##*/} | $VERSION | ✅ | ✅ | ✅ | ✅ PASS |" >> "$RESULTS_FILE"
    ((PASSED++))
  else
    case $EXIT_CODE in
      1)
        echo -e "${RED}✗ $distro: Installation failed${NC}"
        echo "| $distro | $image | ${PKG_FILE##*/} | N/A | N/A | N/A | N/A | ❌ Install failed |" >> "$RESULTS_FILE"
        ;;
      2)
        echo -e "${RED}✗ $distro: Completions missing${NC}"
        echo "| $distro | $image | ${PKG_FILE##*/} | Installed | ❌ | ? | ? | ❌ Completions |" >> "$RESULTS_FILE"
        ;;
      3)
        echo -e "${RED}✗ $distro: Man page missing${NC}"
        echo "| $distro | $image | ${PKG_FILE##*/} | Installed | ✅ | ❌ | ? | ❌ Man page |" >> "$RESULTS_FILE"
        ;;
      4)
        echo -e "${RED}✗ $distro: SystemD service missing${NC}"
        echo "| $distro | $image | ${PKG_FILE##*/} | Installed | ✅ | ✅ | ❌ | ❌ SystemD |" >> "$RESULTS_FILE"
        ;;
      *)
        echo -e "${RED}✗ $distro: Unknown error (exit $EXIT_CODE)${NC}"
        echo "| $distro | $image | ${PKG_FILE##*/} | N/A | N/A | N/A | N/A | ❌ Unknown error |" >> "$RESULTS_FILE"
        ;;
    esac
    echo -e "${RED}Output: $TEST_OUTPUT${NC}"
    ((FAILED++))
  fi

  echo ""
done

echo "" >> "$RESULTS_FILE"
echo "## Summary" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "- **Passed:** $PASSED" >> "$RESULTS_FILE"
echo "- **Failed:** $FAILED" >> "$RESULTS_FILE"
echo "- **Total:** $((PASSED + FAILED))" >> "$RESULTS_FILE"

echo "==============================================="
echo -e "${GREEN}Passed: $PASSED${NC} | ${RED}Failed: $FAILED${NC}"
echo "Results written to $RESULTS_FILE"
echo "==============================================="

if [ $FAILED -gt 0 ]; then
  exit 1
fi
