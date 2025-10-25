#!/usr/bin/env python3
"""
SteganoEXE - Custom Steganography Tool for Windows Executables
Hides files inside executable (.exe) files
GUI Version
"""

import os
import sys
import argparse
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import threading

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
            
            result = {
                "success": True,
                "message": "File hidden successfully!",
                "original_size": original_size,
                "hidden_size": hidden_size,
                "final_size": new_size,
                "overhead": new_size - original_size
            }
            
            return result
            
        except Exception as e:
            return {"success": False, "message": f"Error: {e}"}
    
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
                return {"success": False, "message": "No hidden data found in this executable"}
            
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
            
            return {"success": True, "message": "File extracted successfully!"}
            
        except Exception as e:
            return {"success": False, "message": f"Error during extraction: {e}"}
    
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
            raise Exception("Decryption failed. Wrong password?")
    
    def detect_stego(self, filename):
        """Check if file contains hidden data"""
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            if self.marker in data:
                marker_pos = data.find(self.marker)
                size_pos = marker_pos + len(self.marker)
                hidden_size = int.from_bytes(data[size_pos:size_pos+8], 'big')
                return {
                    "success": True, 
                    "message": "This executable contains hidden data!",
                    "hidden_size": hidden_size,
                    "data_position": marker_pos
                }
            else:
                return {"success": False, "message": "No hidden data detected"}
        except Exception as e:
            return {"success": False, "message": f"Error: {e}"}


class SteganoEXEGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SteganoEXE - File Hiding Tool")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Initialize SteganoEXE engine
        self.steg = SteganoEXE()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.hide_tab = ttk.Frame(self.notebook)
        self.extract_tab = ttk.Frame(self.notebook)
        self.detect_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.hide_tab, text='Hide File')
        self.notebook.add(self.extract_tab, text='Extract File')
        self.notebook.add(self.detect_tab, text='Detect Hidden Data')
        
        # Setup each tab
        self.setup_hide_tab()
        self.setup_extract_tab()
        self.setup_detect_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief='sunken', anchor='w')
        status_bar.pack(side='bottom', fill='x')
    
    def setup_hide_tab(self):
        # Carrier file selection
        ttk.Label(self.hide_tab, text="Carrier Executable:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.carrier_entry = ttk.Entry(self.hide_tab, width=50)
        self.carrier_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.hide_tab, text="Browse", command=self.browse_carrier).grid(row=0, column=2, padx=5, pady=5)
        
        # File to hide selection
        ttk.Label(self.hide_tab, text="File to Hide:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.secret_entry = ttk.Entry(self.hide_tab, width=50)
        self.secret_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.hide_tab, text="Browse", command=self.browse_secret).grid(row=1, column=2, padx=5, pady=5)
        
        # Output file
        ttk.Label(self.hide_tab, text="Output Executable:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.output_entry = ttk.Entry(self.hide_tab, width=50)
        self.output_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(self.hide_tab, text="Browse", command=self.browse_output).grid(row=2, column=2, padx=5, pady=5)
        
        # Password
        ttk.Label(self.hide_tab, text="Password (optional):").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.password_entry = ttk.Entry(self.hide_tab, width=50, show="*")
        self.password_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Hide button
        ttk.Button(self.hide_tab, text="Hide File", command=self.hide_file).grid(row=4, column=1, pady=10)
        
        # Results frame
        self.results_frame = ttk.LabelFrame(self.hide_tab, text="Results")
        self.results_frame.grid(row=5, column=0, columnspan=3, sticky='we', padx=5, pady=5)
        
        self.results_text = tk.Text(self.results_frame, height=6, width=70)
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def setup_extract_tab(self):
        # Stego file selection
        ttk.Label(self.extract_tab, text="Stego Executable:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.extract_carrier_entry = ttk.Entry(self.extract_tab, width=50)
        self.extract_carrier_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.extract_tab, text="Browse", command=self.browse_extract_carrier).grid(row=0, column=2, padx=5, pady=5)
        
        # Output file
        ttk.Label(self.extract_tab, text="Output File:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.extract_output_entry = ttk.Entry(self.extract_tab, width=50)
        self.extract_output_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.extract_tab, text="Browse", command=self.browse_extract_output).grid(row=1, column=2, padx=5, pady=5)
        
        # Password
        ttk.Label(self.extract_tab, text="Password (if encrypted):").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.extract_password_entry = ttk.Entry(self.extract_tab, width=50, show="*")
        self.extract_password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Extract button
        ttk.Button(self.extract_tab, text="Extract File", command=self.extract_file).grid(row=3, column=1, pady=10)
        
        # Results frame
        self.extract_results_frame = ttk.LabelFrame(self.extract_tab, text="Results")
        self.extract_results_frame.grid(row=4, column=0, columnspan=3, sticky='we', padx=5, pady=5)
        
        self.extract_results_text = tk.Text(self.extract_results_frame, height=6, width=70)
        self.extract_results_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def setup_detect_tab(self):
        # File to check
        ttk.Label(self.detect_tab, text="Executable to Check:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.detect_entry = ttk.Entry(self.detect_tab, width=50)
        self.detect_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.detect_tab, text="Browse", command=self.browse_detect).grid(row=0, column=2, padx=5, pady=5)
        
        # Detect button
        ttk.Button(self.detect_tab, text="Detect Hidden Data", command=self.detect_stego).grid(row=1, column=1, pady=10)
        
        # Results frame
        self.detect_results_frame = ttk.LabelFrame(self.detect_tab, text="Detection Results")
        self.detect_results_frame.grid(row=2, column=0, columnspan=3, sticky='we', padx=5, pady=5)
        
        self.detect_results_text = tk.Text(self.detect_results_frame, height=6, width=70)
        self.detect_results_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def browse_carrier(self):
        filename = filedialog.askopenfilename(
            title="Select Carrier Executable",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.carrier_entry.delete(0, tk.END)
            self.carrier_entry.insert(0, filename)
    
    def browse_secret(self):
        filename = filedialog.askopenfilename(
            title="Select File to Hide",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.secret_entry.delete(0, tk.END)
            self.secret_entry.insert(0, filename)
    
    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Output Executable As",
            defaultextension=".exe",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, filename)
    
    def browse_extract_carrier(self):
        filename = filedialog.askopenfilename(
            title="Select Stego Executable",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.extract_carrier_entry.delete(0, tk.END)
            self.extract_carrier_entry.insert(0, filename)
    
    def browse_extract_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Extracted File As",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.extract_output_entry.delete(0, tk.END)
            self.extract_output_entry.insert(0, filename)
    
    def browse_detect(self):
        filename = filedialog.askopenfilename(
            title="Select Executable to Check",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.detect_entry.delete(0, tk.END)
            self.detect_entry.insert(0, filename)
    
    def hide_file(self):
        carrier = self.carrier_entry.get()
        secret = self.secret_entry.get()
        output = self.output_entry.get()
        password = self.password_entry.get() or None
        
        if not carrier or not secret or not output:
            messagebox.showerror("Error", "Please fill in all required fields")
            return
        
        self.status_var.set("Hiding file...")
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Processing... Please wait.\n")
        
        # Run in a separate thread to prevent GUI freezing
        def run_hide():
            result = self.steg.hide_file(carrier, secret, output, password)
            self.root.after(0, self.hide_complete, result)
        
        thread = threading.Thread(target=run_hide)
        thread.daemon = True
        thread.start()
    
    def hide_complete(self, result):
        self.results_text.delete(1.0, tk.END)
        if result["success"]:
            self.results_text.insert(tk.END, f"✓ {result['message']}\n\n")
            self.results_text.insert(tk.END, f"Original size: {result['original_size']} bytes\n")
            self.results_text.insert(tk.END, f"Hidden data: {result['hidden_size']} bytes\n")
            self.results_text.insert(tk.END, f"Final size: {result['final_size']} bytes\n")
            self.results_text.insert(tk.END, f"Overhead: {result['overhead']} bytes\n")
            self.status_var.set("File hidden successfully")
            messagebox.showinfo("Success", "File hidden successfully!")
        else:
            self.results_text.insert(tk.END, f"✗ {result['message']}\n")
            self.status_var.set("Error hiding file")
            messagebox.showerror("Error", result["message"])
    
    def extract_file(self):
        carrier = self.extract_carrier_entry.get()
        output = self.extract_output_entry.get()
        password = self.extract_password_entry.get() or None
        
        if not carrier or not output:
            messagebox.showerror("Error", "Please fill in all required fields")
            return
        
        self.status_var.set("Extracting file...")
        self.extract_results_text.delete(1.0, tk.END)
        self.extract_results_text.insert(tk.END, "Processing... Please wait.\n")
        
        # Run in a separate thread to prevent GUI freezing
        def run_extract():
            result = self.steg.extract_file(carrier, output, password)
            self.root.after(0, self.extract_complete, result)
        
        thread = threading.Thread(target=run_extract)
        thread.daemon = True
        thread.start()
    
    def extract_complete(self, result):
        self.extract_results_text.delete(1.0, tk.END)
        if result["success"]:
            self.extract_results_text.insert(tk.END, f"✓ {result['message']}\n")
            self.status_var.set("File extracted successfully")
            messagebox.showinfo("Success", "File extracted successfully!")
        else:
            self.extract_results_text.insert(tk.END, f"✗ {result['message']}\n")
            self.status_var.set("Error extracting file")
            messagebox.showerror("Error", result["message"])
    
    def detect_stego(self):
        filename = self.detect_entry.get()
        
        if not filename:
            messagebox.showerror("Error", "Please select a file to check")
            return
        
        self.status_var.set("Detecting hidden data...")
        self.detect_results_text.delete(1.0, tk.END)
        self.detect_results_text.insert(tk.END, "Processing... Please wait.\n")
        
        # Run in a separate thread to prevent GUI freezing
        def run_detect():
            result = self.steg.detect_stego(filename)
            self.root.after(0, self.detect_complete, result)
        
        thread = threading.Thread(target=run_detect)
        thread.daemon = True
        thread.start()
    
    def detect_complete(self, result):
        self.detect_results_text.delete(1.0, tk.END)
        if result["success"]:
            self.detect_results_text.insert(tk.END, f"✓ {result['message']}\n")
            self.detect_results_text.insert(tk.END, f"Hidden data size: {result['hidden_size']} bytes\n")
            self.detect_results_text.insert(tk.END, f"Data starts at byte: {result['data_position']}\n")
            self.status_var.set("Hidden data detected")
        else:
            self.detect_results_text.insert(tk.END, f"✗ {result['message']}\n")
            self.status_var.set("No hidden data detected")


def main():
    # Check if we're running in GUI mode or CLI mode
    if len(sys.argv) > 1:
        # CLI mode
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
            result = steg.hide_file(args.carrier, args.secret, args.output, args.password)
            if result["success"]:
                print(f"[✓] {result['message']}")
                print(f"    Original size: {result['original_size']} bytes")
                print(f"    Hidden data: {result['hidden_size']} bytes")
                print(f"    Final size: {result['final_size']} bytes")
                print(f"    Overhead: {result['overhead']} bytes")
            else:
                print(f"[!] {result['message']}")
        
        elif args.action == 'extract':
            if not all([args.carrier, args.secret]):
                print("[!] Please provide --carrier and --secret (output file) arguments")
                return
            result = steg.extract_file(args.carrier, args.secret, args.password)
            if result["success"]:
                print(f"[✓] {result['message']}")
            else:
                print(f"[!] {result['message']}")
        
        elif args.action == 'detect':
            if not args.carrier:
                print("[!] Please provide --carrier argument")
                return
            result = steg.detect_stego(args.carrier)
            if result["success"]:
                print(f"[✓] {result['message']}")
                print(f"    Hidden data size: {result['hidden_size']} bytes")
                print(f"    Data starts at byte: {result['data_position']}")
            else:
                print(f"[!] {result['message']}")
    else:
        # GUI mode
        root = tk.Tk()
        app = SteganoEXEGUI(root)
        root.mainloop()


if __name__ == "__main__":
    main()