#!/usr/bin/env python3
"""
SteganoEXE - Custom Steganography Tool for Windows Executables
Hides files inside executable (.exe) files without breaking functionality
"""

import os
import sys
import argparse
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

class SteganoEXE:
    def __init__(self):
        self.marker = b'STEGANOEXE_v1.0:'  # Unique marker to identify hidden data
    
    def hide_file(self, carrier_exe, file_to_hide, output_exe, password=None):
        """
        Hide a file inside an executable
        """
        try:
            # Read carrier executable
            print(f"[+] Reading carrier executable: {carrier_exe}")
            with open(carrier_exe, 'rb') as f:
                carrier_data = f.read()
            
            # Read file to hide
            print(f"[+] Reading file to hide: {file_to_hide}")
            with open(file_to_hide, 'rb') as f:
                hidden_data = f.read()
            
            # Encrypt data if password provided
            if password:
                print("[+] Encrypting hidden data...")
                hidden_data = self.encrypt_data(hidden_data, password)
            
            # Prepare hidden data with marker and size
            hidden_size = len(hidden_data).to_bytes(8, 'big')
            stego_data = carrier_data + self.marker + hidden_size + hidden_data
            
            # Write the new executable
            print(f"[+] Creating stego executable: {output_exe}")
            with open(output_exe, 'wb') as f:
                f.write(stego_data)
            
            # Calculate statistics
            original_size = os.path.getsize(carrier_exe)
            new_size = os.path.getsize(output_exe)
            hidden_size = len(hidden_data)
            
            print(f"\n[✓] Success! File hidden successfully!")
            print(f"    Original size: {original_size} bytes")
            print(f"    Hidden data: {hidden_size} bytes")
            print(f"    Final size: {new_size} bytes")
            print(f"    Overhead: {new_size - original_size} bytes")
            
            return True
            
        except Exception as e:
            print(f"[!] Error: {e}")
            return False
    
    def extract_file(self, stego_exe, output_file, password=None):
        """
        Extract a hidden file from an executable
        """
        try:
            # Read stego executable
            print(f"[+] Reading stego executable: {stego_exe}")
            with open(stego_exe, 'rb') as f:
                data = f.read()
            
            # Find the marker
            marker_position = data.find(self.marker)
            if marker_position == -1:
                print("[!] No hidden data found in this executable")
                return False
            
            print("[+] Hidden data marker found!")
            
            # Extract size and data
            size_position = marker_position + len(self.marker)
            hidden_size = int.from_bytes(data[size_position:size_position+8], 'big')
            hidden_data = data[size_position+8:size_position+8+hidden_size]
            
            # Decrypt if password provided
            if password:
                print("[+] Decrypting hidden data...")
                hidden_data = self.decrypt_data(hidden_data, password)
            
            # Write extracted file
            print(f"[+] Writing extracted file: {output_file}")
            with open(output_file, 'wb') as f:
                f.write(hidden_data)
            
            print(f"[✓] File extracted successfully!")
            return True
            
        except Exception as e:
            print(f"[!] Error during extraction: {e}")
            return False
    
    def encrypt_data(self, data, password):
        """Encrypt data using AES"""
        key = hashlib.sha256(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv + ct_bytes
    
    def decrypt_data(self, data, password):
        """Decrypt data using AES"""
        try:
            key = hashlib.sha256(password.encode()).digest()
            iv = data[:16]
            ct = data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size)
        except Exception as e:
            print(f"[!] Decryption failed. Wrong password?")
            raise e
    
    def detect_stego(self, filename):
        """Check if file contains hidden data"""
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            if self.marker in data:
                print("[✓] This executable contains hidden data!")
                marker_pos = data.find(self.marker)
                size_pos = marker_pos + len(self.marker)
                hidden_size = int.from_bytes(data[size_pos:size_pos+8], 'big')
                print(f"    Hidden data size: {hidden_size} bytes")
                print(f"    Data starts at byte: {marker_pos}")
                return True
            else:
                print("[!] No hidden data detected")
                return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='SteganoEXE - Hide files in executables')
    parser.add_argument('action', choices=['hide', 'extract', 'detect'], help='Action to perform')
    parser.add_argument('--carrier', help='Carrier executable file')
    parser.add_argument('--secret', help='File to hide or output file for extraction')
    parser.add_argument('--output', help='Output stego executable')
    parser.add_argument('--password', help='Password for encryption (optional)')
    
    args = parser.parse_args()
    steg = SteganoEXE()
    
    if args.action == 'hide':
        if not all([args.carrier, args.secret, args.output]):
            print("[!] Please provide --carrier, --secret, and --output arguments")
            return
        steg.hide_file(args.carrier, args.secret, args.output, args.password)
    
    elif args.action == 'extract':
        if not all([args.carrier, args.secret]):
            print("[!] Please provide --carrier and --secret (output file) arguments")
            return
        steg.extract_file(args.carrier, args.secret, args.password)
    
    elif args.action == 'detect':
        if not args.carrier:
            print("[!] Please provide --carrier argument")
            return
        steg.detect_stego(args.carrier)

if __name__ == "__main__":
    main()