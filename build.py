"""One-command build: python build.py  ->  dist/AliasVault(.exe)  (a single double-clickable app)."""
import subprocess, sys

def run(*a):
    subprocess.check_call([sys.executable, "-m", *a])

run("pip", "install", "-r", "requirements.txt", "pyinstaller")
run("PyInstaller", "--onefile", "--windowed", "--clean", "--name", "AliasVault",
    "--hidden-import", "segno", "aliasvault.py")
print("\nDone. Your app is in the 'dist' folder.")
