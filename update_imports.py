#!/usr/bin/env python3
"""
Script to update all Python imports from 'medusa' to 'supreme2l'
"""

import os
import re
from pathlib import Path

def update_imports_in_file(file_path):
    """Update imports in a single file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Track if we made changes
        original_content = content
        
        # Update import statements
        # Pattern for: from supreme2l.module import something
        content = re.sub(r'from\s+medusa\.', 'from supreme2l.', content)
        
        # Pattern for: import supreme2l.module
        content = re.sub(r'import\s+medusa\.', 'import supreme2l.', content)
        
        # Pattern for: from supreme2l import something
        content = re.sub(r'from\s+medusa\s+import', 'from supreme2l import', content)
        
        # Pattern for: import supreme2l
        content = re.sub(r'import\s+medusa\b', 'import supreme2l', content)
        
        # Update docstrings and comments that mention Supreme 2 Light
        content = re.sub(r'\bMEDUSA\b', 'Supreme 2 Light', content)
        
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
    python_files = []
    
    # Find all Python files
    for root, dirs, files in os.walk(project_root):
        # Skip virtual environments and hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['venv', '.venv', 'env', '__pycache__']]
        
        for file in files:
            if file.endswith('.py'):
                python_files.append(Path(root) / file)
    
    print(f"Found {len(python_files)} Python files")
    
    updated_count = 0
    for file_path in python_files:
        if update_imports_in_file(file_path):
            print(f"Updated: {file_path.relative_to(project_root)}")
            updated_count += 1
    
    print(f"\nUpdated {updated_count} files")
    
    # Also update .md files
    print("\nUpdating documentation files...")
    md_files = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['venv', '.venv', 'env', '__pycache__']]
        
        for file in files:
            if file.endswith('.md'):
                md_files.append(Path(root) / file)
    
    md_updated = 0
    for file_path in md_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Update medusa references in markdown
            content = re.sub(r'\bmedusa\b', 's2l', content, flags=re.IGNORECASE)
            content = re.sub(r'\bMEDUSA\b', 'Supreme 2 Light', content)
            content = re.sub(r'\.medusa\.yml\b', '.supreme2l.yml', content)
            content = re.sub(r'\.medusa/', '.supreme2l/', content)
            
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Updated docs: {file_path.relative_to(project_root)}")
                md_updated += 1
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    print(f"\nUpdated {md_updated} documentation files")

if __name__ == '__main__':
    main()