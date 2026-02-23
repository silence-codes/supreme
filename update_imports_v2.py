#!/usr/bin/env python3
"""
Enhanced script to update all remaining 'medusa' references
"""

import os
import re
from pathlib import Path

def update_file_content(file_path, patterns):
    """Update content in a file using multiple patterns"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        for pattern, replacement in patterns:
            content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def update_yaml_rule_files(file_path):
    """Update YAML rule files (special handling for rule IDs)"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Update MEDUSA- prefix to SUPREME2L- in rule IDs
        content = re.sub(r'\bMEDUSA-', 'SUPREME2L-', content)
        
        # Update comments mentioning MEDUSA
        content = re.sub(r'# MEDUSA ', '# Supreme 2 Light ', content)
        content = re.sub(r'# MEDUSA\n', '# Supreme 2 Light\n', content)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing YAML {file_path}: {e}")
        return False

def main():
    project_root = Path.cwd()
    
    # Patterns for different file types
    general_patterns = [
        (r'\.medusa/', r'.supreme2l/'),
        (r'\.medusa\.yml\b', r'.supreme2l.yml'),
        (r'\bmedusa-security\b', r'supreme2l'),
        (r'\bmedusa:test\b', r'supreme2l:test'),
        (r'pip install medusa-security', r'pip install supreme2l'),
        (r'medusa scan', r's2l scan'),
        (r'medusa init', r's2l init'),
        (r'medusa install', r's2l install'),
        (r'medusa --version', r's2l --version'),
        (r'medusa --help', r's2l --help'),
        (r'black --check medusa/', r'black --check supreme2l/'),
        (r'ruff check medusa/', r'ruff check supreme2l/'),
        (r'mypy medusa/', r'mypy supreme2l/'),
    ]
    
    # Update all files
    updated_count = 0
    
    # Walk through all files
    for root, dirs, files in os.walk(project_root):
        # Skip virtual environments and hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['venv', '.venv', 'env', '__pycache__']]
        
        for file in files:
            file_path = Path(root) / file
            
            # Skip our own script
            if file_path.name in ['update_imports.py', 'update_imports_v2.py']:
                continue
            
            # Handle YAML rule files specially
            if file.endswith('.yaml') or file.endswith('.yml'):
                if update_yaml_rule_files(file_path):
                    print(f"Updated YAML: {file_path.relative_to(project_root)}")
                    updated_count += 1
                continue
            
            # Handle other files
            if update_file_content(file_path, general_patterns):
                print(f"Updated: {file_path.relative_to(project_root)}")
                updated_count += 1
    
    # Special handling for specific files
    special_files = [
        '.gitignore',
        '.github/workflows/test.yml',
        '.github/PULL_REQUEST_TEMPLATE.md',
        '.github/ISSUE_TEMPLATE/bug_report.md',
        '.github/ISSUE_TEMPLATE/scanner_request.md',
        'MANIFEST.in',
        'Formula/medusa-security.rb',
        'examples/pre-commit-config.yaml',
        'examples/medusa.example.yml',
        'examples/gitlab-ci.yml',
        'examples/github-action.yml',
        'Dockerfile.simple',
        'supreme2l/platform/tool_cache.py',
        'supreme2l/platform/install_manifest.py',
    ]
    
    for rel_path in special_files:
        file_path = project_root / rel_path
        if file_path.exists():
            if update_file_content(file_path, general_patterns):
                print(f"Updated special: {rel_path}")
                updated_count += 1
    
    print(f"\nTotal files updated: {updated_count}")
    
    # Rename Formula file
    formula_old = project_root / 'Formula' / 'medusa-security.rb'
    formula_new = project_root / 'Formula' / 'supreme2l.rb'
    if formula_old.exists():
        try:
            formula_old.rename(formula_new)
            print(f"Renamed: {formula_old.relative_to(project_root)} -> {formula_new.relative_to(project_root)}")
            
            # Update content of renamed file
            with open(formula_new, 'r', encoding='utf-8') as f:
                content = f.read()
            
            content = re.sub(r'class MedusaSecurity', 'class Supreme2l', content)
            content = re.sub(r'medusa_security-', 'supreme2l-', content)
            content = re.sub(r'medusa-security', 'supreme2l', content)
            
            with open(formula_new, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Updated content of renamed formula file")
            
        except Exception as e:
            print(f"Error renaming formula file: {e}")
    
    # Rename example config file
    example_old = project_root / 'examples' / 'medusa.example.yml'
    example_new = project_root / 'examples' / 'supreme2l.example.yml'
    if example_old.exists():
        try:
            example_old.rename(example_new)
            print(f"Renamed: {example_old.relative_to(project_root)} -> {example_new.relative_to(project_root)}")
        except Exception as e:
            print(f"Error renaming example file: {e}")

if __name__ == '__main__':
    main()