import os
import subprocess

# Get all Python files in the folder
folder_path = os.getcwd()  # Current folder
python_files = ["dns_resolver.py","root_server.py", "TLD_sever.py","auth_server.py"]

# Execute each Python file
for file in python_files:
    print(f"Running {file}...")
    subprocess.run(["python", file])
