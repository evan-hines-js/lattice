#!/usr/bin/env bash
# Check for common security anti-patterns in Rust code
# Usage: ./scripts/check-security-patterns.sh
# Requires: gawk (GNU awk) for BEGINFILE support

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cd "$PROJECT_ROOT"

# Check for gawk
if ! command -v gawk &> /dev/null; then
    echo "Error: gawk is required but not installed."
    echo "Install with: apt-get install gawk (Ubuntu) or brew install gawk (macOS)"
    exit 1
fi

echo "Running security pattern checks..."
echo ""

VIOLATIONS=0

# Common AWK preamble to track test modules
AWK_TEST_TRACKING='
BEGINFILE { in_test_mod = 0 }
/^[[:space:]]*#\[cfg\(test\)\]/ { in_test_mod = 1 }
'

# =============================================================================
# Check 1: Hardcoded secrets patterns
# =============================================================================
echo "=== Checking for potential hardcoded secrets ==="

SECRETS_AWK="${AWK_TEST_TRACKING}"'
!in_test_mod && /(password|secret|api_key|apikey|credential)[[:space:]]*=[[:space:]]*"[^"]+"/ {
    # Skip common false positives
    if (/assert|mock|Mock|sample|Sample|example|Example|fixture|test_|_test/) next
    print FILENAME ":" FNR ": " $0
    found++
}
END { exit (found > 0 ? 1 : 0) }
'

SECRETS_MATCHES=$(find crates -name "*.rs" -not -path "*/tests/*" -exec gawk "$SECRETS_AWK" {} + 2>/dev/null | head -10 || true)
if [[ -n "$SECRETS_MATCHES" ]]; then
    echo "$SECRETS_MATCHES"
    echo -e "${YELLOW}WARNING: Potential hardcoded secrets found (review manually)${NC}"
else
    echo -e "${GREEN}PASSED: No obvious hardcoded secrets${NC}"
fi
echo ""

# =============================================================================
# Check 2: Weak crypto algorithms
# =============================================================================
echo "=== Checking for weak cryptographic algorithms ==="

WEAK_CRYPTO_AWK="${AWK_TEST_TRACKING}"'
!in_test_mod && /\b(md5|sha1|sha-1|des|3des|rc4|arcfour|blowfish)\b/ {
    # Skip comments
    if (/^[[:space:]]*(\/\/|\/\*|\*)/) next
    print FILENAME ":" FNR ": " $0
    found++
}
END { exit (found > 0 ? 1 : 0) }
'

WEAK_MATCHES=$(find crates -name "*.rs" -not -path "*/tests/*" -exec gawk "$WEAK_CRYPTO_AWK" {} + 2>/dev/null | head -10 || true)
if [[ -n "$WEAK_MATCHES" ]]; then
    echo "$WEAK_MATCHES"
    echo -e "${RED}FAILED: Weak cryptographic algorithms found${NC}"
    VIOLATIONS=$((VIOLATIONS + 1))
else
    echo -e "${GREEN}PASSED: No weak cryptographic algorithms${NC}"
fi
echo ""

# =============================================================================
# Check 3: Verify FIPS crypto backend
# =============================================================================
echo "=== Checking FIPS crypto configuration ==="
if grep -q 'features.*=.*\["aws-lc-rs"' Cargo.toml && grep -q 'aws-lc-rs' Cargo.toml; then
    echo -e "${GREEN}PASSED: aws-lc-rs FIPS backend configured${NC}"
else
    echo -e "${RED}FAILED: aws-lc-rs FIPS backend not properly configured${NC}"
    VIOLATIONS=$((VIOLATIONS + 1))
fi
echo ""

# =============================================================================
# Check 4: Unsafe blocks
# =============================================================================
echo "=== Checking for unsafe blocks ==="

UNSAFE_AWK='
BEGINFILE { in_test_mod = 0 }
/^[[:space:]]*#\[cfg\(test\)\]/ { in_test_mod = 1 }
!in_test_mod && /unsafe[[:space:]]*\{/ {
    print FILENAME ":" FNR ": " $0
}
'

UNSAFE_MATCHES=$(find crates -name "*.rs" -not -path "*/tests/*" -exec gawk "$UNSAFE_AWK" {} + 2>/dev/null | head -10 || true)
UNSAFE_COUNT=$(find crates -name "*.rs" -not -path "*/tests/*" -exec gawk "$UNSAFE_AWK" {} + 2>/dev/null | wc -l | tr -d ' ' || echo "0")

if [[ "$UNSAFE_COUNT" -gt 0 ]]; then
    echo "$UNSAFE_MATCHES"
    echo -e "${YELLOW}WARNING: $UNSAFE_COUNT unsafe block(s) found in production code (review manually)${NC}"
else
    echo -e "${GREEN}PASSED: No unsafe blocks in production code${NC}"
fi
echo ""

# =============================================================================
# Check 5: SQL/Command injection patterns
# =============================================================================
echo "=== Checking for potential injection vulnerabilities ==="

INJECTION_AWK="${AWK_TEST_TRACKING}"'
!in_test_mod && /format!\s*\([^)]*\$\{|execute\s*\(\s*&format!/ {
    print FILENAME ":" FNR ": " $0
    found++
}
END { exit (found > 0 ? 1 : 0) }
'

INJECTION_MATCHES=$(find crates -name "*.rs" -not -path "*/tests/*" -exec gawk "$INJECTION_AWK" {} + 2>/dev/null | head -10 || true)
if [[ -n "$INJECTION_MATCHES" ]]; then
    echo "$INJECTION_MATCHES"
    echo -e "${YELLOW}WARNING: Potential injection vulnerability patterns found (review manually)${NC}"
else
    echo -e "${GREEN}PASSED: No obvious injection patterns${NC}"
fi
echo ""

# =============================================================================
# Check 6: Verify TLS configuration
# =============================================================================
echo "=== Checking TLS configuration ==="
HAS_RUSTLS=$(grep -rE 'rustls-tls|tls-rustls' Cargo.toml crates/*/Cargo.toml 2>/dev/null || true)
HAS_NATIVE=$(grep -rE 'native-tls' Cargo.toml crates/*/Cargo.toml 2>/dev/null || true)
if [[ -n "$HAS_RUSTLS" ]] && [[ -z "$HAS_NATIVE" ]]; then
    echo -e "${GREEN}PASSED: Using rustls-tls (not native-tls)${NC}"
elif [[ -n "$HAS_NATIVE" ]]; then
    echo -e "${YELLOW}WARNING: native-tls found - prefer rustls-tls${NC}"
    echo "$HAS_NATIVE"
else
    echo -e "${YELLOW}WARNING: No TLS configuration found${NC}"
fi
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=== Security Check Summary ==="
if [[ "$VIOLATIONS" -eq 0 ]]; then
    echo -e "${GREEN}All critical security checks passed${NC}"
    exit 0
else
    echo -e "${RED}$VIOLATIONS critical security violation(s) found${NC}"
    exit 1
fi
