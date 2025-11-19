#!/bin/bash
# Manual pre-commit checks script
# Run this before committing to ensure code quality

set -e  # Exit on any error

echo "Running pre-commit checks..."
echo ""

echo "1️⃣  Formatting code with cargo fmt..."
cargo fmt --all
echo "✅ Formatting complete"
echo ""

echo "2️⃣  Running clippy checks..."
cargo clippy --all-targets --all-features -- -D warnings
echo "✅ Clippy checks passed"
echo ""

echo "3️⃣  Running in-memory WebAuthn integration test..."
cargo test --test webauthn_inmemory_test --no-default-features
echo "✅ In-memory test passed"
echo ""

echo "✨ All pre-commit checks passed!"
