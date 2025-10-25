# stegano_exe

'stegano_exe_gui.py' NEW GUI FOR EASY USE..

Python steganography tool for executables

Requirements: pycryptodome

Install Dependencies
pip install pycryptodome

How to use??
Hide a file: python stegano_exe.py hide --carrier carrier.exe --secret secret.txt --output hidden.exe --password mypass123
Extract a file: python stegano_exe.py extract --carrier hidden.exe --secret extracted_secret.txt --password mypass123
Detect hidden data: python stegano_exe.py detect --carrier hidden.exe

