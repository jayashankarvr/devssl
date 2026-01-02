#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

VERSION=$1
ERRORS=0
WARNINGS=0

if [ -z "$VERSION" ]; then
    echo -e "${RED}Error: Version argument required${RESET}"
    echo -e "${YELLOW}Usage: ./scripts/pre-release-check.sh 0.2.1${RESET}"
    exit 1
fi

echo -e "${BLUE}${BOLD}Pre-release check for v$VERSION${RESET}"
echo ""

# Check version consistency
echo -e "${BOLD}Checking version consistency...${RESET}"
if grep -q "^version = \"$VERSION\"" Cargo.toml; then
    echo -e "${GREEN}✓${RESET} Cargo.toml"
else
    echo -e "${RED}✗ Cargo.toml MISMATCH${RESET}"
    echo -e "${YELLOW}  → Fix: Update version in Cargo.toml to \"$VERSION\"${RESET}"
    ERRORS=$((ERRORS + 1))
fi

if grep -q "^## \[$VERSION\]" CHANGELOG.md; then
    echo -e "${GREEN}✓${RESET} CHANGELOG.md"
else
    echo -e "${RED}✗ CHANGELOG.md MISSING${RESET}"
    echo -e "${YELLOW}  → Fix: Add '## [$VERSION] - $(date +%Y-%m-%d)' section to CHANGELOG.md${RESET}"
    ERRORS=$((ERRORS + 1))
fi

if grep -q "version \"$VERSION\"" Formula/devssl.rb; then
    echo -e "${GREEN}✓${RESET} Formula/devssl.rb"
else
    echo -e "${RED}✗ Formula/devssl.rb MISMATCH${RESET}"
    echo -e "${YELLOW}  → Fix: Update version in Formula/devssl.rb to \"$VERSION\"${RESET}"
    ERRORS=$((ERRORS + 1))
fi

# Check for placeholder SHA256s in formula
if grep -q "PLACEHOLDER" Formula/devssl.rb; then
    echo -e "${ORANGE}⚠${RESET}  Formula/devssl.rb has PLACEHOLDER checksums"
    echo -e "${YELLOW}  → Warning: Update SHA256 checksums after building release binaries${RESET}"
    WARNINGS=$((WARNINGS + 1))
fi

# Run tests
echo ""
echo -e "${BOLD}Running tests...${RESET}"
if cargo test --quiet 2>&1 | tee /tmp/test-output.txt | tail -5; then
    if grep -q "test result: ok" /tmp/test-output.txt; then
        echo -e "${GREEN}✓${RESET} All tests passed"
    else
        echo -e "${RED}✗ Tests failed${RESET}"
        echo -e "${YELLOW}  → Fix: Run 'cargo test' to see failures${RESET}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${RED}✗ Tests failed${RESET}"
    echo -e "${YELLOW}  → Fix: Run 'cargo test' to see failures${RESET}"
    ERRORS=$((ERRORS + 1))
fi
rm -f /tmp/test-output.txt

# Check code format
echo ""
echo -e "${BOLD}Checking code format...${RESET}"
if cargo fmt --check > /dev/null 2>&1; then
    echo -e "${GREEN}✓${RESET} Code formatted"
else
    echo -e "${RED}✗ Code not formatted${RESET}"
    echo -e "${YELLOW}  → Fix: Run 'cargo fmt' to format code${RESET}"
    ERRORS=$((ERRORS + 1))
fi

# Check lints
echo ""
echo -e "${BOLD}Checking lints...${RESET}"
CLIPPY_OUTPUT=$(cargo clippy --all-targets --all-features --quiet 2>&1)
if echo "$CLIPPY_OUTPUT" | grep -q "warning:"; then
    echo -e "${ORANGE}⚠${RESET}  Clippy warnings found:"
    echo "$CLIPPY_OUTPUT" | grep "warning:" | head -5
    echo -e "${YELLOW}  → Warning: Fix clippy warnings with 'cargo clippy --fix'${RESET}"
    WARNINGS=$((WARNINGS + 1))
elif echo "$CLIPPY_OUTPUT" | grep -q "error:"; then
    echo -e "${RED}✗ Clippy errors found${RESET}"
    echo "$CLIPPY_OUTPUT" | grep "error:" | head -5
    echo -e "${YELLOW}  → Fix: Run 'cargo clippy --all-targets --all-features' to see all errors${RESET}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓${RESET} No clippy issues"
fi

# Build release
echo ""
echo -e "${BOLD}Building release...${RESET}"
if cargo build --release --quiet 2>&1 | tee /tmp/build-output.txt | tail -3; then
    if [ -f target/release/devssl ]; then
        echo -e "${GREEN}✓${RESET} Release build successful"
    else
        echo -e "${RED}✗ Release build failed${RESET}"
        echo -e "${YELLOW}  → Fix: Run 'cargo build --release' to see errors${RESET}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${RED}✗ Release build failed${RESET}"
    echo -e "${YELLOW}  → Fix: Run 'cargo build --release' to see errors${RESET}"
    ERRORS=$((ERRORS + 1))
fi
rm -f /tmp/build-output.txt

# Check git status
echo ""
echo -e "${BOLD}Git status...${RESET}"
GIT_STATUS=$(git status --short)
if [ -n "$GIT_STATUS" ]; then
    MODIFIED_COUNT=$(echo "$GIT_STATUS" | grep -c "^ M\|^M \|^MM" || true)
    UNTRACKED_COUNT=$(echo "$GIT_STATUS" | grep -c "^??" || true)

    if [ "$MODIFIED_COUNT" -gt 0 ]; then
        echo -e "${ORANGE}⚠${RESET}  $MODIFIED_COUNT modified file(s)"
        echo "$GIT_STATUS" | grep "^ M\|^M \|^MM" | head -5
        WARNINGS=$((WARNINGS + 1))
    fi

    if [ "$UNTRACKED_COUNT" -gt 0 ]; then
        echo -e "${ORANGE}⚠${RESET}  $UNTRACKED_COUNT untracked file(s)"
        echo "$GIT_STATUS" | grep "^??" | head -5
    fi
else
    echo -e "${GREEN}✓${RESET} Working directory clean"
fi

# Check for uncommitted files that shouldn't be committed
EXCLUDED_FILES=("TODO.md" "RELEASE_PLAN.md" "humanize_analysis.md" "test-all-features.sh")
for file in "${EXCLUDED_FILES[@]}"; do
    if echo "$GIT_STATUS" | grep -q "^A.*$file"; then
        echo -e "${RED}✗ $file is staged but should not be committed${RESET}"
        echo -e "${YELLOW}  → Fix: Run 'git reset HEAD $file'${RESET}"
        ERRORS=$((ERRORS + 1))
    fi
done

# Final summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ All checks passed! Ready to release v$VERSION${RESET}"
    echo ""
    echo -e "${BOLD}Next steps:${RESET}"
    echo -e "  ${GREEN}git add -A${RESET}"
    echo -e "  ${GREEN}git commit -m 'Release v$VERSION'${RESET}"
    echo -e "  ${GREEN}git tag -a v$VERSION -m 'v$VERSION'${RESET}"
    echo -e "  ${GREEN}git push origin main v$VERSION${RESET}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${ORANGE}${BOLD}⚠ $WARNINGS warning(s) found${RESET}"
    echo -e "${YELLOW}You can proceed with the release, but consider fixing warnings first.${RESET}"
    echo ""
    echo -e "${BOLD}Next steps:${RESET}"
    echo -e "  ${YELLOW}git add -A${RESET}"
    echo -e "  ${YELLOW}git commit -m 'Release v$VERSION'${RESET}"
    echo -e "  ${YELLOW}git tag -a v$VERSION -m 'v$VERSION'${RESET}"
    echo -e "  ${YELLOW}git push origin main v$VERSION${RESET}"
    exit 0
else
    echo -e "${RED}${BOLD}✗ $ERRORS error(s) found${RESET}"
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${ORANGE}${BOLD}⚠ $WARNINGS warning(s) found${RESET}"
    fi
    echo ""
    echo -e "${RED}${BOLD}Cannot proceed with release. Please fix the errors above.${RESET}"
    exit 1
fi
