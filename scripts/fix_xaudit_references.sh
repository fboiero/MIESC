#!/bin/bash

################################################################################
# Fix xaudit References - Replace with miesc
# This script finds and replaces all references to "xaudit" with "miesc"
#
# Author: Fernando Boiero
# Project: MIESC
################################################################################

echo "🔍 Finding all references to 'xaudit' in the project..."
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Count references
total=$(grep -r "xaudit" --exclude-dir=.git --exclude-dir=node_modules --exclude="*.pyc" --exclude="fix_xaudit_references.sh" . 2>/dev/null | wc -l | tr -d ' ')

echo -e "${YELLOW}Found ${total} references to 'xaudit'${NC}"
echo ""

if [ "$total" -eq "0" ]; then
    echo -e "${GREEN}✓ No xaudit references found! Project is clean.${NC}"
    exit 0
fi

echo "Files to update:"
grep -r "xaudit" --exclude-dir=.git --exclude-dir=node_modules --exclude="*.pyc" --exclude="fix_xaudit_references.sh" . 2>/dev/null | cut -d: -f1 | sort -u | while read file; do
    count=$(grep -c "xaudit" "$file" 2>/dev/null || echo "0")
    echo -e "  ${BLUE}${file}${NC} (${count} occurrences)"
done

echo ""
read -p "Do you want to proceed with replacements? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "🔧 Replacing 'xaudit' with 'miesc'..."
echo ""

# Note: We keep the script name as xaudit.py for backward compatibility
# but update documentation references

# Find and replace in all files except .git and node_modules
find . -type f \
    -not -path "./.git/*" \
    -not -path "./node_modules/*" \
    -not -name "*.pyc" \
    -not -name "fix_xaudit_references.sh" \
    -exec grep -l "xaudit" {} \; 2>/dev/null | while read file; do

    # Skip binary files
    if file "$file" | grep -q "text"; then
        # Replace xaudit with miesc (case-insensitive for URLs)
        # But keep xaudit.py script name
        sed -i.bak \
            -e 's|github\.com/fboiero/xaudit|github.com/fboiero/MIESC|g' \
            -e 's|fboiero\.github\.io/xaudit|fboiero.github.io/MIESC|g' \
            -e '/python xaudit\.py/! s/xaudit/miesc/g' \
            "$file"

        # Remove backup file
        rm -f "${file}.bak"

        echo -e "${GREEN}✓${NC} Updated: $file"
    fi
done

echo ""
echo -e "${GREEN}✓ All references updated!${NC}"
echo ""
echo "Summary of changes:"
echo "  - Repository URLs: github.com/fboiero/MIESC → github.com/fboiero/MIESC"
echo "  - Website URLs: fboiero.github.io/xaudit → fboiero.github.io/MIESC"
echo "  - Project name: xaudit → miesc (in documentation)"
echo "  - Script name: kept as 'python xaudit.py' for backward compatibility"
echo ""
echo "Note: The main script is still called 'xaudit.py' for now."
echo "Consider renaming it to 'miesc.py' in a future version."
echo ""
