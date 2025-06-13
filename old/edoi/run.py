import subprocess
import time
import os

# Paths to the Python files
files = [
    {
        "path": r"C:\Users\Awesome Kuhn Family\Documents\Tristan\httpe\shadownet\edoi.py",
        "output": "edoi_output.txt"
    },
    {
        "path": r"C:\Users\Awesome Kuhn Family\Documents\Tristan\httpe\edoi\main.py",
        "output": "main_output.txt"
    },
    {
        "path": r"C:\Users\Awesome Kuhn Family\Documents\Tristan\httpe\edoi\test.py",
        "output": "test_output.txt"
    }
]

processes = []

for file in files:
    print(f"Starting {file['path']}...")

    # Open output file
    output_file = open(file['output'], "w")

    # Start the process and redirect stdout and stderr to the output file
    process = subprocess.Popen(
        ["python", file["path"]],
        stdout=output_file,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_CONSOLE  # Open each in a new console window (Windows only)
    )
    processes.append((process, output_file))

    # Delay before starting the next file
    time.sleep(2)

print("All scripts launched.")

# Optionally keep the main script running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopping all scripts...")
    for process, output_file in processes:
        process.terminate()
        output_file.close()
