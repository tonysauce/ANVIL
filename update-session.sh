#!/usr/bin/env bash
# update-session.sh - Session management for CLAUDE.md
# Ensures session context stays current between Claude Code sessions

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get current date
CURRENT_DATE=$(date '+%B %d, %Y')
SHORT_DATE=$(date '+%Y-%m-%d')

# CLAUDE.md file path
CLAUDE_MD="CLAUDE.md"

if [ ! -f "$CLAUDE_MD" ]; then
    print_error "CLAUDE.md not found in current directory"
    exit 1
fi

# Function to update session date in CLAUDE.md
update_session_date() {
    print_info "Updating session date to $CURRENT_DATE..."
    
    # Update current session context date
    if grep -q "## Current Session Context" "$CLAUDE_MD"; then
        # Extract the line and update the date
        sed -i "s/## Current Session Context ([^)]*)/## Current Session Context ($CURRENT_DATE)/" "$CLAUDE_MD"
        print_success "Updated current session context date"
    else
        print_warning "Current Session Context section not found"
    fi
}

# Function to archive previous session and start new one
archive_previous_session() {
    print_info "Archiving previous session status..."
    
    # Find and update session end status
    if grep -q "## Session End Status" "$CLAUDE_MD"; then
        # Add previous session to archive if it doesn't exist
        if ! grep -q "## Previous Sessions" "$CLAUDE_MD"; then
            # Insert previous sessions section before session end status
            sed -i '/## Session End Status/i ## Previous Sessions\n' "$CLAUDE_MD"
        fi
        
        # Update the date in session end status
        sed -i "s/## Session End Status ([^)]*)/## Session End Status ($CURRENT_DATE)/" "$CLAUDE_MD"
        print_success "Updated session end status date"
    else
        print_warning "Session End Status section not found"
    fi
}

# Function to prompt for session updates
prompt_session_update() {
    echo ""
    print_info "Session Update Prompts:"
    echo "======================"
    echo ""
    
    read -p "What work was completed in the previous session? (brief summary): " PREV_WORK
    read -p "What is the current status/issue being worked on? " CURRENT_STATUS
    read -p "Any new issues discovered? (optional): " NEW_ISSUES
    
    echo ""
    print_info "Session Update Summary:"
    echo "Previous work: $PREV_WORK"
    echo "Current status: $CURRENT_STATUS"
    if [ -n "$NEW_ISSUES" ]; then
        echo "New issues: $NEW_ISSUES"
    fi
    echo ""
    
    read -p "Add this to CLAUDE.md? (y/N): " CONFIRM
    
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        # Add session update to CLAUDE.md
        {
            echo ""
            echo "### Session Update ($SHORT_DATE)"
            echo "- **Previous work**: $PREV_WORK"
            echo "- **Current status**: $CURRENT_STATUS"
            if [ -n "$NEW_ISSUES" ]; then
                echo "- **New issues**: $NEW_ISSUES"
            fi
        } >> session_update_temp.md
        
        # Insert before "## Commands to Remember" section
        if grep -q "## Commands to Remember" "$CLAUDE_MD"; then
            sed -i '/## Commands to Remember/e cat session_update_temp.md' "$CLAUDE_MD"
            rm session_update_temp.md
            print_success "Session update added to CLAUDE.md"
        else
            # Append to end of file
            cat session_update_temp.md >> "$CLAUDE_MD"
            rm session_update_temp.md
            print_success "Session update appended to CLAUDE.md"
        fi
    fi
}

# Main execution
main() {
    echo ""
    echo "🔄 Claude Code Session Update Manager"
    echo "====================================="
    echo ""
    
    update_session_date
    archive_previous_session
    
    echo ""
    read -p "Would you like to add session notes? (y/N): " ADD_NOTES
    
    if [[ "$ADD_NOTES" =~ ^[Yy]$ ]]; then
        prompt_session_update
    fi
    
    echo ""
    print_success "Session update completed!"
    print_info "CLAUDE.md has been updated with current session date"
    print_warning "Remember to commit these changes: git add CLAUDE.md && git commit -m 'docs: Update session context'"
}

# Run main function
main "$@"