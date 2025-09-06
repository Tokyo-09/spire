import customtkinter as ctk
from tkinter import filedialog
import subprocess
import os
import threading
from PIL import Image, ImageTk
import uuid

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rust Sentinel Antivirus")
        self.root.geometry("800x600")
        self.db_path = "../db/malware.db"
        
        # Set modern appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create main frame with gradient background
        self.main_frame = ctk.CTkFrame(root, corner_radius=20, fg_color=("#1a1a2e", "#e0e0e0"))
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Title with anime-inspired font
        self.title_label = ctk.CTkLabel(
            self.main_frame,
            text="🌸 Rust Sentinel Antivirus 🌸",
            font=("Anime Ace", 28, "bold"),
            text_color=("#ff6b6b", "#ff4d4d")
        )
        self.title_label.pack(pady=20)
        
        # Path selection
        self.path_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.path_frame.pack(pady=10, fill="x", padx=20)
        
        self.path_entry = ctk.CTkEntry(
            self.path_frame,
            width=500,
            placeholder_text="Select path to scan...",
            font=("Roboto", 14),
            corner_radius=10
        )
        self.path_entry.pack(side="left", padx=5)
        
        self.browse_button = ctk.CTkButton(
            self.path_frame,
            text="Browse",
            command=self.browse_path,
            width=100,
            fg_color=("#4a4e69", "#9a8c98"),
            hover_color=("#5e60ce", "#c9ada7"),
            corner_radius=10
        )
        self.browse_button.pack(side="left", padx=5)
        
        # Algorithm selection
        self.algo_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.algo_frame.pack(pady=10, fill="x", padx=20)
        
        ctk.CTkLabel(
            self.algo_frame,
            text="Hash Algorithm:",
            font=("Roboto", 14)
        ).pack(side="left", padx=5)
        
        self.algo_var = ctk.StringVar(value="md5")
        self.algo_menu = ctk.CTkComboBox(
            self.algo_frame,
            values=["md5", "sha256", "sha512"],
            variable=self.algo_var,
            width=150,
            font=("Roboto", 14),
            dropdown_fg_color=("#4a4e69", "#9a8c98"),
            button_color=("#5e60ce", "#c9ada7"),
            button_hover_color=("#48cae4", "#f4acb7")
        )
        self.algo_menu.pack(side="left", padx=5)
        
        # Scan button with animation
        self.scan_button = ctk.CTkButton(
            self.main_frame,
            text="🔍 Scan Now",
            command=self.start_scan_thread,
            font=("Anime Ace", 16, "bold"),
            fg_color=("#ff6b6b", "#ff4d4d"),
            hover_color=("#ff8787", "#ff6666"),
            corner_radius=15,
            height=50
        )
        self.scan_button.pack(pady=20)
        
        # Result display
        self.result_text = ctk.CTkTextbox(
            self.main_frame,
            height=200,
            font=("Roboto", 12),
            fg_color=("#2b2d42", "#edf2f4"),
            corner_radius=10
        )
        self.result_text.pack(pady=10, padx=20, fill="both")
        
        # Progress bar for scan
        self.progress = ctk.CTkProgressBar(
            self.main_frame,
            mode="indeterminate",
            width=300
        )
        self.progress.pack(pady=10)
        self.progress.set(0)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            self.main_frame,
            text="Ready to scan!",
            font=("Roboto", 12, "italic"),
            text_color=("#90be6d", "#43aa8b")
        )
        self.status_label.pack(pady=5)
        
    def browse_path(self):
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.path_entry.delete(0, ctk.END)
            self.path_entry.insert(0, path)
            self.status_label.configure(text="Path selected! Ready to scan.")
    
    def start_scan_thread(self):
        self.scan_button.configure(state="disabled")
        self.progress.start()
        self.status_label.configure(text="Scanning in progress...")
        threading.Thread(target=self.run_scan, daemon=True).start()
    
    def run_scan(self):
        path = self.path_entry.get()
        algo = self.algo_var.get()
        
        if not path:
            self.result_text.insert(ctk.END, "Please select a path to scan.\n")
            self.finalize_scan()
            return
        
        cmd = ["../target/release/av_cli", "--db", self.db_path, "--path", path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.result_text.delete(1.0, ctk.END)
            self.result_text.insert(ctk.END, result.stdout + result.stderr)
            self.status_label.configure(text="Scan completed successfully!")
        except Exception as e:
            self.result_text.insert(ctk.END, f"Error running scan: {e}\n")
            self.status_label.configure(text="Scan failed!")
        finally:
            self.finalize_scan()
    
    def finalize_scan(self):
        self.progress.stop()
        self.progress.set(0)
        self.scan_button.configure(state="normal")

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    root = ctk.CTk()
    app = AntivirusGUI(root)
    root.mainloop()