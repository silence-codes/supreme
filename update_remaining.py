#!/usr/bin/env python3
"""
Script to update remaining medusa references including class names, paths, and URLs
"""

import os
import re
from pathlib import Path

def update_file(file_path):
    """Update all remaining medusa references in a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Update class names
        content = re.sub(r'\bMedusaParallelScanner\b', 'Supreme2lParallelScanner', content)
        content = re.sub(r'\bMedusaConfig\b', 'Supreme2lConfig', content)
        content = re.sub(r'\bMedusaCacheManager\b', 'Supreme2lCacheManager', content)
        content = re.sub(r'\bMedusaReportGenerator\b', 'Supreme2lReportGenerator', content)
        
        # Update directory paths
        content = re.sub(r'~/.medusa/', '~/.supreme2l/', content)
        content = re.sub(r'\.medusa/', '.supreme2l/', content)
        content = re.sub(r'/opt/medusa', '/opt/supreme2l', content)
        
        # Update file paths in IDE integration
        content = re.sub(r'\.claude/agents/medusa/', '.claude/agents/supreme2l/', content)
        content = re.sub(r'\.claude/commands/medusa-', '.claude/commands/s2l-', content)
        content = re.sub(r'\.gemini/commands/medusa-', '.gemini/commands/s2l-', content)
        
        # Update command references
        content = re.sub(r'/medusa-scan\b', '/s2l-scan', content)
        content = re.sub(r'/medusa-install\b', '/s2l-install', content)
        content = re.sub(r'medusa-scan\.md', 's2l-scan.md', content)
        content = re.sub(r'medusa-install\.md', 's2l-install.md', content)
        content = re.sub(r'medusa-scan\.toml', 's2l-scan.toml', content)
        content = re.sub(r'medusa-install\.toml', 's2l-install.toml', content)
        
        # Update GitHub URLs
        content = re.sub(r'github\.com/Pantheon-Security/medusa', 'github.com/Zeinullahh/Supreme-2-light', content)
        content = re.sub(r'pantheonsecurity\.io', 'silenceai.net', content)
        content = re.sub(r'Pantheon Security', 'Silence AI', content)
        
        # Update email addresses
        content = re.sub(r'support@pantheonsecurity\.io', 'support@silenceai.net', content)
        content = re.sub(r'security@pantheonsecurity\.io', 'security@silenceai.net', content)
        
        # Update documentation URLs
        content = re.sub(r'https://docs\.pantheonsecurity\.io', 'https://docs.silenceai.net', content)
        
        # Update wheel file names
        content = re.sub(r'medusa_security-', 'supreme2l-', content)
        
        # Update in comments
        content = re.sub(r'# MEDUSA', '# Supreme 2 Light', content)
        content = re.sub(r'# medusa', '# supreme2l', content)
        
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
    
    # Walk through all files
    for root, dirs, files in os.walk(project_root):
        # Skip virtual environments and hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['venv', '.venv', 'env', '__pycache__']]
        
        for file in files:
            file_path = Path(root) / file
            
            # Skip our own scripts
            if file_path.name in ['update_imports.py', 'update_imports_v2.py', 'update_remaining.py']:
                continue
            
            # Skip binary files
            if file_path.suffix in ['.whl', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf']:
                continue
            
            # Update file
            if update_file(file_path):
                print(f"Updated: {file_path.relative_to(project_root)}")
                updated_count += 1
    
    print(f"\nTotal files updated: {updated_count}")
    
    # Rename directories
    dirs_to_rename = [
        (project_root / '.claude' / 'agents' / 'medusa', project_root / '.claude' / 'agents' / 'supreme2l'),
        (project_root / 'medusa' / 'rules', project_root / 'supreme2l' / 'rules'),
    ]
    
    for old_dir, new_dir in dirs_to_rename:
        if old_dir.exists():
            try:
                old_dir.rename(new_dir)
                print(f"Renamed directory: {old_dir.relative_to(project_root)} -> {new_dir.relative_to(project_root)}")
            except Exception as e:
                print(f"Error renaming directory {old_dir}: {e}")

if __name__ == '__main__':
    main()