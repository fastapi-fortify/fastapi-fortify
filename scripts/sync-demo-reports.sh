#!/bin/bash

# Sync test reports to GitHub Pages demo
# Usage: ./scripts/sync-demo-reports.sh

set -e

echo "🔄 Syncing test reports to GitHub Pages demo..."

# Check if test_reports directory exists
if [ ! -d "test_reports" ]; then
    echo "❌ Error: test_reports directory not found"
    echo "Please run tests first to generate reports"
    exit 1
fi

# Create docs directory if it doesn't exist
mkdir -p docs

# Copy individual report files (GitHub Pages structure is flat)
echo "📂 Copying reports..."
cp test_reports/*.html docs/
cp test_reports/*.json docs/

# List what was copied
echo "✅ Copied the following reports:"
ls -la docs/*.html docs/*.json 2>/dev/null || echo "No HTML/JSON reports found"

# Check if there are changes to commit
if git diff --quiet docs/*.html docs/*.json 2>/dev/null; then
    echo "ℹ️  No changes detected in demo reports"
else
    echo "📝 Changes detected - ready to commit"
    echo ""
    echo "Next steps:"
    echo "  git add docs/*.html docs/*.json"
    echo "  git commit -m 'Update demo test reports'"
    echo "  git push origin main"
    echo ""
    echo "Or let GitHub Actions handle it automatically when you push test_reports/ changes!"
fi

echo ""
echo "🌐 Demo will be available at: https://fastapi-fortify.github.io/fastapi-fortify/"
echo "📊 Test reports will be at:"
echo "  - Coverage: https://fastapi-fortify.github.io/fastapi-fortify/coverage_report.html"
echo "  - Security: https://fastapi-fortify.github.io/fastapi-fortify/security_test_report.html"
echo "  - Performance: https://fastapi-fortify.github.io/fastapi-fortify/performance_benchmark_report.html"