#!/usr/bin/env python3
"""
Final cleanup script to handle all remaining medusa references
"""

import os
import re
import shutil
from pathlib import Path

def update_file_content(file_path):
    """Update all remaining medusa references in a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Update all remaining medusa references
        content = re.sub(r'\bmedusa\b', 'supreme2l', content, flags=re.IGNORECASE)
        content = re.sub(r'\bMEDUSA\b', 'SUPREME2L', content)
        
        # Update specific patterns that might have been missed
        content = re.sub(r'medusa\.sh', 'supreme2l.sh', content)
        content = re.sub(r'medusa-report\.py', 'supreme2l-report.py', content)
        content = re.sub(r'medusa\.security', 'supreme2l.security', content)
        
        # Update Docker image names
        content = re.sub(r'medusa:', 'supreme2l:', content)
        content = re.sub(r'medusa-security:', 'supreme2l:', content)
        content = re.sub(r'medusa-test:', 'supreme2l-test:', content)
        
        # Update container names
        content = re.sub(r'container_name: medusa', 'container_name: supreme2l', content)
        
        # Update command references in help text
        content = re.sub(r"'medusa ", "'s2l ", content)
        content = re.sub(r'"medusa ', '"s2l ', content)
        content = re.sub(r'`medusa ', '`s2l ', content)
        
        # Update GitHub URLs
        content = re.sub(r'github\.com/pantheon-security/medusa', 'github.com/Zeinullahh/Supreme-2-light', content, flags=re.IGNORECASE)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def rename_directories():
    """Rename directories that still have medusa in their names"""
    project_root = Path.cwd()
    
    # Check if medusa/rules directory exists and needs to be moved
    medusa_rules_dir = project_root / 'medusa' / 'rules'
    supreme2l_rules_dir = project_root / 'supreme2l' / 'rules'
    
    if medusa_rules_dir.exists() and not supreme2l_rules_dir.exists():
        try:
            # Create supreme2l/rules directory if it doesn't exist
            supreme2l_rules_dir.parent.mkdir(parents=True, exist_ok=True)
            
            # Move contents
            for item in medusa_rules_dir.iterdir():
                shutil.move(str(item), str(supreme2l_rules_dir / item.name))
            
            # Remove empty directory
            medusa_rules_dir.rmdir()
            print(f"Moved rules from {medusa_rules_dir} to {supreme2l_rules_dir}")
        except Exception as e:
            print(f"Error moving rules directory: {e}")
    
    # Check for .claude/agents/medusa directory
    claude_medusa_dir = project_root / '.claude' / 'agents' / 'medusa'
    claude_supreme2l_dir = project_root / '.claude' / 'agents' / 'supreme2l'
    
    if claude_medusa_dir.exists() and not claude_supreme2l_dir.exists():
        try:
            claude_medusa_dir.rename(claude_supreme2l_dir)
            print(f"Renamed directory: {claude_medusa_dir} -> {claude_supreme2l_dir}")
        except Exception as e:
            print(f"Error renaming claude directory: {e}")

def main():
    project_root = Path.cwd()
    updated_count = 0
    
    # First rename directories
    rename_directories()
    
    # Walk through all files
    for root, dirs, files in os.walk(project_root):
        # Skip virtual environments and hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['venv', '.venv', 'env', '__pycache__']]
        
        for file in files:
            file_path = Path(root) / file
            
            # Skip our own scripts
            if file_path.name in ['update_imports.py', 'update_imports_v2.py', 'update_remaining.py', 'final_cleanup.py']:
                continue
            
            # Skip binary files
            if file_path.suffix in ['.whl', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf']:
                continue
            
            # Update file
            if update_file_content(file_path):
                print(f"Updated: {file_path.relative_to(project_root)}")
                updated_count += 1
    
    print(f"\nTotal files updated: {updated_count}")
    
    # Update MANIFEST.in
    manifest_path = project_root / 'MANIFEST.in'
    if manifest_path.exists():
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            content = re.sub(r'recursive-include medusa ', 'recursive-include supreme2l ', content)
            
            with open(manifest_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Updated MANIFEST.in")
        except Exception as e:
            print(f"Error updating MANIFEST.in: {e}")
    
    # Update .gitignore
    gitignore_path = project_root / '.gitignore'
    if gitignore_path.exists():
        try:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Remove medusa/rules references
            lines = content.split('\n')
            new_lines = []
            for line in lines:
                if not line.strip().startswith('medusa/rules/'):
                    new_lines.append(line)
            
            with open(gitignore_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(new_lines))
            print(f"Cleaned .gitignore")
        except Exception as e:
            print(f"Error updating .gitignore: {e}")

if __name__ == '__main__':
    main()