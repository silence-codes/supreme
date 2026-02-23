#!/usr/bin/env python3
"""
Script to update internal variable names from medusa to supreme2l
"""

import os
import re
from pathlib import Path

def update_variable_names(file_path):
    """Update internal variable names in a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Update variable names
        content = re.sub(r'\bmedusa_version\b', 'supreme2l_version', content)
        content = re.sub(r'\bmedusa_script\b', 'supreme2l_script', content)
        content = re.sub(r'\bmedusa_dir\b', 'supreme2l_dir', content)
        content = re.sub(r'\bmedusa_mcp_config\b', 'supreme2l_mcp_config', content)
        
        # Update method names
        content = re.sub(r'\bwas_installed_by_medusa\b', 'was_installed_by_supreme2l', content)
        content = re.sub(r'\bget_medusa_installed_tools\b', 'get_supreme2l_installed_tools', content)
        
        # Update environment variable
        content = re.sub(r'\bMEDUSA_ALLOW_LOCALHOST\b', 'SUPREME2L_ALLOW_LOCALHOST', content)
        
        # Update JSON field names
        content = re.sub(r'"medusa_version"', '"supreme2l_version"', content)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    project_root = Path.cwd()
    updated_count = 0
    
    # Files that need variable name updates
    target_files = [
        'supreme2l/cli.py',
        'supreme2l/core/parallel.py',
        'supreme2l/core/reporter.py',
        'supreme2l/platform/install_manifest.py',
        'supreme2l/platform/version_manager.py',
        'supreme2l/ide/claude_code.py',
        'supreme2l/scanners/mcp_config_scanner.py',
        'supreme2l/dependencies.json',
        'supreme2l/tool-versions.lock',
        'scripts/check_dependencies.py',
        'scripts/update_tool_versions.py',
    ]
    
    for rel_path in target_files:
        file_path = project_root / rel_path
        if file_path.exists():
            if update_variable_names(file_path):
                print(f"Updated variables: {rel_path}")
                updated_count += 1
    
    print(f"\nTotal files updated: {updated_count}")

if __name__ == '__main__':
    main()