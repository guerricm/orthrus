import os
import glob
import shutil

def replace_in_file(filepath, old_str, new_str):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    if old_str in content:
        content = content.replace(old_str, new_str)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    workspace = '/Users/guerricmerle/Documents/workspaces/orthrus'
    
    # 1. Replace strings in all files
    extensions = ['*.java', '*.xml', '*.yaml', '*.yml', '*.properties', '*.md']
    
    for root, dirs, files in os.walk(workspace):
        if '.git' in root or 'target' in root or '.idea' in root:
            continue
        for file in files:
            if any(file.endswith(ext.replace('*', '')) for ext in extensions):
                filepath = os.path.join(root, file)
                try:
                    replace_in_file(filepath, 'ch.hug.security', 'ch.nexsol.security')
                    replace_in_file(filepath, 'ch.hug.orthrusdast', 'ch.nexsol.orthrusdast')
                    replace_in_file(filepath, 'ch.hug.vulnapi', 'ch.nexsol.vulnapi')
                    replace_in_file(filepath, 'ch.hug.', 'ch.nexsol.')
                except Exception as e:
                    print(f"Error processing {filepath}: {e}")

    # 2. Rename directories
    for root, dirs, files in os.walk(workspace, topdown=False):
        if '.git' in root or 'target' in root or '.idea' in root:
            continue
        for dirname in dirs:
            if dirname == 'hug' and os.path.basename(root) == 'ch':
                old_dir = os.path.join(root, dirname)
                new_dir = os.path.join(root, 'nexsol')
                print(f"Renaming {old_dir} to {new_dir}")
                os.rename(old_dir, new_dir)

if __name__ == '__main__':
    main()
