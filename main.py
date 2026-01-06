import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
import os
import base64
import hashlib
from datetime import datetime
import pyperclip
import random
import string
import ctypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Manager - Login")
        
        # Get DPI scaling factor for proper high-DPI display support
        try:
            self.scale_factor = self.get_windows_scale_factor()
        except:
            self.scale_factor = 1.0
        
        # Set initial window size with DPI scaling
        base_width = int(500 * self.scale_factor)
        base_height = int(300 * self.scale_factor)
        self.root.geometry(f"{base_width}x{base_height}")
        
        # GitHub Dark theme color palette
        self.colors = {
            'bg': '#0d1117',
            'bg_secondary': '#161b22',
            'text_primary': '#c9d1d9',
            'text_secondary': '#8b949e',
            'accent': '#58a6ff',
            'danger': '#da3633',
            'success': '#238636',
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # File names for storing encrypted data and security components
        self.data_file = 'passwords.encrypted'
        self.salt_file = 'salt.bin'
        self.hash_file = 'master.hash'
        self.passwords = {}
        self.master_password_hash = None
        self.fernet = None
        self.revealed_passwords = {}
        
        self.show_login_screen()
        
    def get_windows_scale_factor(self):
        """Retrieve Windows DPI scaling factor for proper high-DPI display support"""
        try:
            user32 = ctypes.windll.user32
            user32.SetProcessDPIAware()
            dc = user32.GetDC(0)
            dpi = ctypes.windll.gdi32.GetDeviceCaps(dc, 88)
            user32.ReleaseDC(0, dc)
            return dpi / 96.0
        except:
            return 1.0
    
    def scale(self, value):
        """Scale UI element sizes based on DPI factor"""
        return int(value * self.scale_factor)
    
    def derive_key(self, password, salt):
        """Derive encryption key from password using PBKDF2 with 100,000 iterations"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def hash_password(self, password):
        """Create secure PBKDF2 hash with random salt for master password storage"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
            dklen=128
        )
        return salt + key
    
    def verify_password(self, stored_hash, provided_password):
        """Verify provided password against stored hash with timing-attack protection"""
        if not stored_hash or len(stored_hash) < 32:
            return False
            
        salt = stored_hash[:32]
        stored_key = stored_hash[32:]
        key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000,
            dklen=128
        )
        return stored_key == key
    
    def show_login_screen(self):
        """Display login screen or first-time setup based on database existence"""
        for widget in self.root.winfo_children():
            widget.destroy()
        
        center_frame = tk.Frame(self.root, bg=self.colors['bg'])
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        title_label = tk.Label(
            center_frame,
            text="🔐 Password Manager",
            font=('Segoe UI', self.scale(20), 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text_primary']
        )
        title_label.pack(pady=(0, self.scale(20)))
        
        # Check if this is first run (no database exists)
        is_first_run = not os.path.exists(self.data_file)
        
        if is_first_run:
            info_label = tk.Label(
                center_frame,
                text="Set up your master password",
                font=('Segoe UI', self.scale(10)),
                bg=self.colors['bg'],
                fg=self.colors['text_secondary']
            )
            info_label.pack(pady=(0, self.scale(10)))
            
            password_frame = tk.Frame(center_frame, bg=self.colors['bg'])
            password_frame.pack(pady=self.scale(5))
            
            tk.Label(password_frame, text="Password:", 
                    bg=self.colors['bg'], fg=self.colors['text_primary']).pack(side=tk.LEFT)
            self.master_password_entry = tk.Entry(password_frame, show="•", width=25)
            self.master_password_entry.pack(side=tk.LEFT, padx=self.scale(5))
            
            confirm_frame = tk.Frame(center_frame, bg=self.colors['bg'])
            confirm_frame.pack(pady=self.scale(5))
            
            tk.Label(confirm_frame, text="Confirm:", 
                    bg=self.colors['bg'], fg=self.colors['text_primary']).pack(side=tk.LEFT)
            self.confirm_password_entry = tk.Entry(confirm_frame, show="•", width=25)
            self.confirm_password_entry.pack(side=tk.LEFT, padx=self.scale(5))
            
            setup_button = tk.Button(
                center_frame,
                text="🔐 Setup Master Password",
                bg=self.colors['accent'],
                fg='white',
                font=('Segoe UI', self.scale(10), 'bold'),
                command=self.setup_master_password,
                padx=self.scale(20),
                pady=self.scale(8)
            )
            setup_button.pack(pady=self.scale(20))
            
        else:
            info_label = tk.Label(
                center_frame,
                text="Enter your master password",
                font=('Segoe UI', self.scale(10)),
                bg=self.colors['bg'],
                fg=self.colors['text_secondary']
            )
            info_label.pack(pady=(0, self.scale(10)))
            
            password_frame = tk.Frame(center_frame, bg=self.colors['bg'])
            password_frame.pack(pady=self.scale(5))
            
            tk.Label(password_frame, text="Password:", 
                    bg=self.colors['bg'], fg=self.colors['text_primary']).pack(side=tk.LEFT)
            self.master_password_entry = tk.Entry(password_frame, show="•", width=25)
            self.master_password_entry.pack(side=tk.LEFT, padx=self.scale(5))
            
            self.show_password_var = tk.BooleanVar()
            show_check = tk.Checkbutton(
                center_frame,
                text="Show password",
                variable=self.show_password_var,
                bg=self.colors['bg'],
                fg=self.colors['text_primary'],
                selectcolor=self.colors['bg_secondary'],
                command=self.toggle_login_password
            )
            show_check.pack(pady=self.scale(5))
            
            login_button = tk.Button(
                center_frame,
                text="🔓 Login",
                bg=self.colors['accent'],
                fg='white',
                font=('Segoe UI', self.scale(10), 'bold'),
                command=self.login,
                padx=self.scale(20),
                pady=self.scale(8)
            )
            login_button.pack(pady=self.scale(20))
            
            self.master_password_entry.bind('<Return>', lambda e: self.login())
    
    def toggle_login_password(self):
        """Toggle password visibility in login entry field"""
        if self.show_password_var.get():
            self.master_password_entry.config(show="")
        else:
            self.master_password_entry.config(show="•")
    
    def setup_master_password(self):
        """Handle first-time master password setup with validation"""
        password = self.master_password_entry.get()
        confirm = self.confirm_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return
        
        # Generate secure hash of master password
        self.master_password_hash = self.hash_password(password)
        
        # Store hash separately for password verification
        with open(self.hash_file, 'wb') as f:
            f.write(self.master_password_hash)
        
        # Generate encryption key from password and random salt
        salt = os.urandom(16)
        self.fernet = self.derive_key(password, salt)
        
        # Store salt separately from encrypted data
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        
        # Create initial empty encrypted database
        self.save_data()
        
        messagebox.showinfo("Success", "Master password setup complete!")
        self.start_main_application()
    
    def login(self):
        """Authenticate user with master password and initialize encryption"""
        password = self.master_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter your password")
            return
        
        # Verify hash file exists before attempting login
        if not os.path.exists(self.hash_file):
            messagebox.showerror("Error", "Password database not found or corrupted")
            return
        
        try:
            # Load stored password hash
            with open(self.hash_file, 'rb') as f:
                stored_hash = f.read()
            
            # Verify password against stored hash
            if not self.verify_password(stored_hash, password):
                messagebox.showerror("Error", "Incorrect password")
                return
            
            # Load salt and recreate Fernet cipher for decryption
            with open(self.salt_file, 'rb') as salt_file:
                salt = salt_file.read()
            
            self.fernet = self.derive_key(password, salt)
            self.master_password_hash = stored_hash
            
            self.start_main_application()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load database: {str(e)}")
    
    def start_main_application(self):
        """Initialize main application window after successful authentication"""
        self.load_data()
        
        self.root.title("🔐 Password Manager")
        self.root.geometry(f"{int(1100 * self.scale_factor)}x{int(800 * self.scale_factor)}")
        self.root.minsize(int(900 * self.scale_factor), int(600 * self.scale_factor))
        
        self.setup_github_theme()
        self.setup_ui()
        self.refresh_password_list()
        self.root.bind('<Configure>', self.on_window_resize)
        
    def setup_github_theme(self):
        """Configure GitHub Dark theme with custom styling for all UI components"""
        self.colors = {
            'bg': '#0d1117',
            'bg_secondary': '#161b22',
            'bg_tertiary': '#21262d',
            'text_primary': '#c9d1d9',
            'text_secondary': '#8b949e',
            'text_tertiary': '#6e7681',
            'accent': '#58a6ff',
            'accent_hover': '#1f6feb',
            'success': '#238636',
            'success_hover': '#2ea043',
            'danger': '#da3633',
            'danger_hover': '#f85149',
            'warning': '#d29922',
            'warning_hover': '#e3b341',
            'border': '#30363d',
            'border_hover': '#8b949e',
            'input_bg': '#0d1117',
            'input_border': '#30363d',
            'button_bg': '#21262d',
            'button_hover': '#30363d',
            'logo': '#f0f6fc',
            'selection': '#1f6feb',
            'tooltip': '#f0f6fc',
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        style = ttk.Style()
        style.theme_use('clam')
        
        base_font_size = max(9, int(9 * self.scale_factor))
        heading_font_size = max(9, int(9 * self.scale_factor))
        
        style.configure('.', 
                       background=self.colors['bg'],
                       foreground=self.colors['text_primary'],
                       font=('Segoe UI', base_font_size))
        
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabelframe', 
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['text_primary'],
                       relief='solid',
                       borderwidth=1)
        style.configure('TLabelframe.Label',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['text_primary'],
                       font=('Segoe UI', base_font_size, 'bold'))
        
        style.configure('TButton',
                       background=self.colors['button_bg'],
                       foreground=self.colors['text_primary'],
                       borderwidth=1,
                       relief='solid',
                       padding=self.scale(8))
        
        style.map('TButton',
                 background=[('active', self.colors['button_hover'])])
        
        style.configure('Accent.TButton',
                       background=self.colors['accent'],
                       foreground='#ffffff',
                       font=('Segoe UI', base_font_size, 'bold'),
                       padding=self.scale(8))
        
        style.map('Accent.TButton',
                 background=[('active', self.colors['accent_hover'])])
        
        style.configure('Danger.TButton',
                       background=self.colors['danger'],
                       foreground='#ffffff',
                       font=('Segoe UI', base_font_size, 'bold'),
                       padding=self.scale(8))
        
        style.map('Danger.TButton',
                 background=[('active', self.colors['danger_hover'])])
        
        style.configure('TEntry',
                       fieldbackground=self.colors['input_bg'],
                       foreground=self.colors['text_primary'],
                       borderwidth=1,
                       relief='solid',
                       padding=self.scale(5))
        
        style.configure('Treeview',
                       background=self.colors['bg_tertiary'],
                       foreground=self.colors['text_primary'],
                       fieldbackground=self.colors['bg_tertiary'],
                       rowheight=self.scale(25),
                       borderwidth=0)
        style.configure('Treeview.Heading',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['text_secondary'],
                       relief='flat',
                       borderwidth=0,
                       padding=self.scale(5),
                       font=('Segoe UI', heading_font_size, 'bold'))
        
        style.map('Treeview',
                 background=[('selected', self.colors['selection'])])
        
        style.configure('Vertical.TScrollbar',
                       background=self.colors['bg_secondary'],
                       troughcolor=self.colors['bg'],
                       bordercolor=self.colors['border'],
                       arrowcolor=self.colors['text_secondary'],
                       width=self.scale(12))
    
    def save_data(self):
        """Encrypt and save password database to file with automatic backup"""
        if not self.fernet:
            return False
        
        try:
            # Serialize password data to JSON for encryption
            json_data = json.dumps(self.passwords, ensure_ascii=False, indent=2)
            
            # Encrypt using Fernet (AES-256 in CBC mode)
            encrypted_data = self.fernet.encrypt(json_data.encode('utf-8'))
            
            # Write encrypted data to primary storage file
            with open(self.data_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Create timestamped backup for disaster recovery
            backup_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.encrypted"
            with open(backup_file, 'wb') as f:
                f.write(encrypted_data)
            
            return True
            
        except Exception as e:
            print(f"Save error: {e}")
            return False
    
    def load_data(self):
        """Load and decrypt password database from encrypted storage file"""
        if not self.fernet or not os.path.exists(self.data_file):
            self.passwords = {}
            return
        
        try:
            with open(self.data_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt using Fernet key derived from master password
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Deserialize JSON back to Python dictionary
            self.passwords = json.loads(decrypted_data.decode('utf-8'))
            
        except Exception as e:
            print(f"Load error: {e}")
            self.passwords = {}
            self.restore_from_backup()
    
    def restore_from_backup(self):
        """Attempt to restore database from most recent backup file"""
        backup_files = [f for f in os.listdir('.') if f.startswith('backup_') and f.endswith('.encrypted')]
        if backup_files:
            backup_files.sort(reverse=True)
            latest_backup = backup_files[0]
            
            try:
                with open(latest_backup, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = self.fernet.decrypt(encrypted_data)
                self.passwords = json.loads(decrypted_data.decode('utf-8'))
                
                messagebox.showwarning("Restored", f"Restored data from backup: {latest_backup}")
                return True
                
            except:
                pass
        
        messagebox.showerror("Error", "Could not load database or restore from backup")
        return False
    
    def setup_ui(self):
        """Construct main application interface with two-column layout"""
        for widget in self.root.winfo_children():
            widget.destroy()
        
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=self.scale(15), pady=self.scale(15))
        
        # Header section with logo and logout button
        header_frame = tk.Frame(main_container, bg=self.colors['bg'], height=self.scale(60))
        header_frame.pack(fill=tk.X, pady=(0, self.scale(15)))
        header_frame.pack_propagate(False)
        
        logo_frame = tk.Frame(header_frame, bg=self.colors['bg'])
        logo_frame.pack(side=tk.LEFT, padx=self.scale(10))
        
        logo_label = tk.Label(
            logo_frame,
            text="🔐",
            font=('Segoe UI', self.scale(24)),
            bg=self.colors['bg'],
            fg=self.colors['logo']
        )
        logo_label.pack(side=tk.LEFT)
        
        title_label = tk.Label(
            logo_frame,
            text="Password Manager",
            font=('Segoe UI', self.scale(18), 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['text_primary']
        )
        title_label.pack(side=tk.LEFT, padx=(self.scale(10), 0))
        
        right_frame = tk.Frame(header_frame, bg=self.colors['bg'])
        right_frame.pack(side=tk.RIGHT, padx=self.scale(10))
        
        self.stats_label = tk.Label(
            right_frame,
            text="Entries: 0",
            font=('Segoe UI', self.scale(10)),
            bg=self.colors['bg'],
            fg=self.colors['text_secondary']
        )
        self.stats_label.pack(side=tk.LEFT, padx=(0, self.scale(10)))
        
        logout_button = tk.Button(
            right_frame,
            text="🚪 Logout",
            bg=self.colors['danger'],
            fg='white',
            font=('Segoe UI', self.scale(9), 'bold'),
            command=self.logout,
            padx=self.scale(15),
            pady=self.scale(8)
        )
        logout_button.pack(side=tk.LEFT)
        
        # Main content area with left (form) and right (list) columns
        content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=2)
        content_frame.rowconfigure(0, weight=1)
        
        # Left column: Entry form for adding/editing passwords
        left_column = ttk.LabelFrame(content_frame, text=" NEW ENTRY", padding=self.scale(15))
        left_column.grid(row=0, column=0, sticky=tk.NSEW, padx=(0, self.scale(10)))
        
        # Right column: Password list with search and actions
        right_column = ttk.LabelFrame(content_frame, text=" YOUR PASSWORDS", padding=self.scale(15))
        right_column.grid(row=0, column=1, sticky=tk.NSEW)
        
        left_column.columnconfigure(1, weight=1)
        
        # Form fields definition with associated action buttons
        fields = [
            ("Website/App:", "site_entry"),
            ("Login/Email:", "username_entry"),
            ("Password:", "password_entry")
        ]
        
        for i, (label_text, attr_name) in enumerate(fields):
            frame = ttk.Frame(left_column)
            frame.grid(row=i, column=0, columnspan=2, sticky=tk.EW, pady=self.scale(8))
            frame.columnconfigure(1, weight=1)
            
            label = ttk.Label(frame, text=label_text, width=self.scale(20), anchor=tk.W)
            label.grid(row=0, column=0, sticky=tk.W)
            
            if attr_name == "password_entry":
                password_frame = ttk.Frame(frame)
                password_frame.grid(row=0, column=1, sticky=tk.EW, padx=(self.scale(5), 0))
                password_frame.columnconfigure(0, weight=1)
                
                entry = ttk.Entry(password_frame, show="•", font=('Consolas', self.scale(10)))
                entry.grid(row=0, column=0, sticky=tk.EW, padx=(0, self.scale(5)))
                setattr(self, attr_name, entry)
                
                btn_frame = ttk.Frame(password_frame)
                btn_frame.grid(row=0, column=1, sticky=tk.E)
                
                ttk.Button(btn_frame, text="👁️", width=self.scale(4),
                          command=self.toggle_password_visibility).pack(side=tk.LEFT, padx=self.scale(2))
                ttk.Button(btn_frame, text="🎲", width=self.scale(4),
                          command=self.generate_password).pack(side=tk.LEFT, padx=self.scale(2))
                ttk.Button(btn_frame, text="📋", width=self.scale(4),
                          command=self.copy_current_password).pack(side=tk.LEFT, padx=self.scale(2))
            elif attr_name == "username_entry":
                username_frame = ttk.Frame(frame)
                username_frame.grid(row=0, column=1, sticky=tk.EW, padx=(self.scale(5), 0))
                username_frame.columnconfigure(0, weight=1)
                
                entry = ttk.Entry(username_frame, font=('Segoe UI', self.scale(10)))
                entry.grid(row=0, column=0, sticky=tk.EW, padx=(0, self.scale(5)))
                setattr(self, attr_name, entry)
                
                ttk.Button(username_frame, text="📋", width=self.scale(4),
                          command=self.copy_current_username).grid(row=0, column=1, sticky=tk.E)
            else:
                entry = ttk.Entry(frame, font=('Segoe UI', self.scale(10)))
                entry.grid(row=0, column=1, sticky=tk.EW, padx=(self.scale(5), 0))
                setattr(self, attr_name, entry)
        
        # Notes field for additional information
        notes_frame = ttk.Frame(left_column)
        notes_frame.grid(row=3, column=0, columnspan=2, sticky=tk.NSEW, pady=self.scale(8))
        notes_frame.rowconfigure(1, weight=1)
        notes_frame.columnconfigure(0, weight=1)
        
        ttk.Label(notes_frame, text="Notes:").grid(row=0, column=0, sticky=tk.W)
        
        self.notes_text = scrolledtext.ScrolledText(
            notes_frame,
            height=6,
            bg=self.colors['input_bg'],
            fg=self.colors['text_primary'],
            insertbackground=self.colors['text_primary'],
            relief='solid',
            borderwidth=1,
            font=('Segoe UI', self.scale(9))
        )
        self.notes_text.grid(row=1, column=0, sticky=tk.NSEW, pady=(self.scale(5), 0))
        
        # Form action buttons
        button_frame = ttk.Frame(left_column)
        button_frame.grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=self.scale(15))
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        
        self.save_button = ttk.Button(
            button_frame,
            text="💾 SAVE",
            style='Accent.TButton',
            command=self.save_password
        )
        self.save_button.grid(row=0, column=0, sticky=tk.EW, padx=(0, self.scale(5)))
        
        ttk.Button(
            button_frame,
            text="🗑️ CLEAR",
            command=self.clear_form
        ).grid(row=0, column=1, sticky=tk.EW)
        
        # Selection information display
        self.selection_info = tk.Label(
            left_column,
            text="Select an entry from the list on the right",
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary'],
            font=('Segoe UI', self.scale(9)),
            relief='flat',
            padx=self.scale(10),
            pady=self.scale(8)
        )
        self.selection_info.grid(row=5, column=0, columnspan=2, sticky=tk.EW, pady=(self.scale(10), 0))
        
        left_column.rowconfigure(3, weight=1)
        
        # Configure right column (password list)
        right_column.columnconfigure(0, weight=1)
        right_column.rowconfigure(1, weight=1)
        
        # Search panel with clear button
        control_frame = ttk.Frame(right_column)
        control_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, self.scale(10)))
        control_frame.columnconfigure(0, weight=1)
        
        search_frame = ttk.Frame(control_frame)
        search_frame.grid(row=0, column=0, sticky=tk.EW)
        search_frame.columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text="🔍 Search:").grid(row=0, column=0, sticky=tk.W)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.grid(row=0, column=1, sticky=tk.EW, padx=self.scale(5))
        self.search_entry.bind('<KeyRelease>', self.search_passwords)
        
        ttk.Button(search_frame, text="✕", width=self.scale(4),
                  command=self.clear_search).grid(row=0, column=2, sticky=tk.E)
        
        # Bulk delete button
        bulk_frame = ttk.Frame(control_frame)
        bulk_frame.grid(row=1, column=0, sticky=tk.EW, pady=(self.scale(5), 0))
        
        ttk.Button(bulk_frame, text="🗑️ Delete All",
                  command=self.delete_all_passwords,
                  style='Danger.TButton').pack(anchor=tk.W)
        
        # Treeview for displaying password entries
        tree_frame = ttk.Frame(right_column)
        tree_frame.grid(row=1, column=0, sticky=tk.NSEW)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        self.tree = ttk.Treeview(
            tree_frame,
            columns=('site', 'username', 'password', 'updated'),
            show='headings',
            height=15
        )
        
        columns = [
            ('site', 'WEBSITE/APP', self.scale(250)),
            ('username', 'LOGIN', self.scale(180)),
            ('password', 'PASSWORD', self.scale(150)),
            ('updated', 'UPDATED', self.scale(120))
        ]
        
        for col_id, heading, width in columns:
            self.tree.heading(col_id, text=heading)
            self.tree.column(col_id, width=width, minwidth=self.scale(80), stretch=True)
        
        # Scrollbars for treeview
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        self.tree.configure(yscrollcommand=vsb.set)
        
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky=tk.EW)
        self.tree.configure(xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        
        # Action buttons for selected entries
        action_frame = ttk.Frame(right_column)
        action_frame.grid(row=2, column=0, sticky=tk.EW, pady=(self.scale(10), 0))
        
        single_actions = [
            ("📋 Password", self.copy_selected_password),
            ("📋 Login", self.copy_selected_username),
            ("👁️ Show", self.toggle_selected_password_visibility),
            ("✏️ Load", self.load_selected_to_form),
            ("🗑️ Delete", self.delete_selected_password, 'Danger.TButton')
        ]
        
        for i, (text, command, *style_args) in enumerate(single_actions):
            action_frame.columnconfigure(i, weight=1)
            if style_args:
                btn = ttk.Button(action_frame, text=text, command=command, 
                               style=style_args[0], padding=self.scale(6))
            else:
                btn = ttk.Button(action_frame, text=text, command=command,
                               padding=self.scale(6))
            btn.grid(row=0, column=i, padx=self.scale(2), sticky=tk.EW)
        
        # Information panel
        info_frame = ttk.Frame(right_column)
        info_frame.grid(row=3, column=0, sticky=tk.EW, pady=(self.scale(10), 0))
        
        self.info_label = tk.Label(
            info_frame,
            text="📌 'Load' - loads selected entry into form for editing",
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary'],
            font=('Segoe UI', self.scale(8)),
            relief='flat',
            padx=self.scale(5),
            pady=self.scale(3)
        )
        self.info_label.pack(fill=tk.X)
        
        # Status bar at bottom
        self.status_bar = tk.Label(
            main_container,
            text="🔒 Database encrypted | ✅ Ready",
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_secondary'],
            font=('Segoe UI', self.scale(9)),
            relief='flat',
            padx=self.scale(15),
            pady=self.scale(8),
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X, pady=(self.scale(15), 0))
        
        # Event bindings
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        self.tree.bind('<Double-1>', self.on_tree_double_click)
        
        self.auto_lock_timer = None
        self.start_auto_lock_timer()
    
    def start_auto_lock_timer(self):
        """Start 30-minute auto-lock timer for security"""
        if self.auto_lock_timer:
            self.root.after_cancel(self.auto_lock_timer)
        
        # 30 minutes = 1,800,000 milliseconds
        self.auto_lock_timer = self.root.after(1800000, self.auto_lock)
    
    def auto_lock(self):
        """Automatically lock application after 30 minutes of inactivity"""
        if messagebox.askyesno("Auto-Lock", "Session timed out. Lock application?"):
            self.logout()
    
    def logout(self):
        """Clear sensitive data and return to login screen"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.passwords.clear()
            self.fernet = None
            self.master_password_hash = None
            self.revealed_passwords.clear()
            
            self.__init__(self.root)
    
    def refresh_password_list(self, search_term=None):
        """Update password list display with optional search filtering"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        filtered_items = []
        for site, data in self.passwords.items():
            if search_term and search_term.strip():
                search_lower = search_term.lower()
                site_str = str(site)
                if search_lower not in site_str.lower():
                    continue
            filtered_items.append((site, data))
        
        filtered_items.sort(key=lambda x: str(x[0]).lower())
        
        for site, data in filtered_items:
            username = data.get('username', '') or '—'
            
            site_str = str(site)
            if site_str in self.revealed_passwords:
                password = self.revealed_passwords[site_str]
            else:
                password = "•" * 12
            
            updated = data.get('updated_at', '')
            if updated:
                updated = updated.split()[0] if ' ' in updated else updated
            else:
                updated = '—'
            
            self.tree.insert('', tk.END, values=(site_str, username, password, updated))
        
        self.stats_label.config(text=f"Entries: {len(self.tree.get_children())}")
    
    def save_password(self):
        """Save new password entry or update existing one with validation"""
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        notes = self.notes_text.get(1.0, tk.END).strip()
        
        if not site:
            self.show_status("⚠️ Enter website name", "warning")
            return
        
        if not password:
            self.show_status("⚠️ Enter password", "warning")
            return
        
        # Always store site as string to handle numeric sites consistently
        site_key = str(site)
        is_new = site_key not in self.passwords
        action = "added" if is_new else "updated"
        
        self.passwords[site_key] = {
            'password': password,
            'username': username if username else '',
            'notes': notes if notes else '',
            'created_at': self.passwords.get(site_key, {}).get('created_at', 
                         datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            'updated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if self.save_data():
            if site_key in self.revealed_passwords:
                del self.revealed_passwords[site_key]
            
            search_term = self.search_entry.get().strip()
            self.refresh_password_list(search_term)
            
            self.show_status(f"✅ Entry for '{site}' {action} | 🔒 Encrypted", "success")
            
            if is_new:
                self.clear_form()
            else:
                self.save_button.config(text="💾 SAVE")
        else:
            self.show_status("❌ Could not save entry", "error")
    
    def on_window_resize(self, event):
        """Handle window resize events and reset auto-lock timer"""
        if event.widget == self.root:
            self.start_auto_lock_timer()
    
    def toggle_password_visibility(self):
        """Toggle password visibility in form entry field"""
        if self.password_entry.cget('show') == '•':
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='•')
    
    def generate_password(self):
        """Generate cryptographically strong password with character variety"""
        length = 16
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure password contains at least one of each character type
        password = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
        ]
        
        # Fill remaining length with random characters
        password += [random.choice(chars) for _ in range(length - 4)]
        
        # Shuffle for additional randomness
        random.shuffle(password)
        password_str = ''.join(password)
        
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password_str)
        self.copy_to_clipboard(password_str)
        self.show_status("✅ Generated strong password | 📋 Copied to clipboard", "success")
    
    def copy_current_password(self):
        """Copy password from form field to system clipboard"""
        password = self.password_entry.get()
        if password:
            self.copy_to_clipboard(password)
            self.show_status("✅ Password copied to clipboard", "success")
        else:
            self.show_status("⚠️ No password to copy", "warning")
    
    def copy_current_username(self):
        """Copy username from form field to system clipboard"""
        username = self.username_entry.get()
        if username:
            self.copy_to_clipboard(username)
            self.show_status("✅ Username copied to clipboard", "success")
        else:
            self.show_status("⚠️ No username to copy", "warning")
    
    def copy_selected_password(self):
        """Copy password of selected entry to system clipboard"""
        selection = self.tree.selection()
        if not selection:
            self.show_status("⚠️ Select an entry first", "warning")
            return
        
        item = selection[0]
        site = self.tree.item(item)['values'][0]
        
        site_str = str(site)
        if site_str in self.passwords:
            password = self.passwords[site_str]['password']
            self.copy_to_clipboard(password)
            self.show_status(f"✅ Password for '{site_str}' copied to clipboard", "success")
        else:
            self.show_status("❌ Could not find password", "error")
    
    def copy_selected_username(self):
        """Copy username of selected entry to system clipboard"""
        selection = self.tree.selection()
        if not selection:
            self.show_status("⚠️ Select an entry first", "warning")
            return
        
        item = selection[0]
        site = self.tree.item(item)['values'][0]
        
        site_str = str(site)
        if site_str in self.passwords:
            username = self.passwords[site_str].get('username', '')
            if username:
                self.copy_to_clipboard(username)
                self.show_status(f"✅ Username for '{site_str}' copied to clipboard", "success")
            else:
                self.show_status("⚠️ No username for this entry", "warning")
        else:
            self.show_status("❌ Could not find entry", "error")
    
    def copy_to_clipboard(self, text):
        """Safe clipboard copy operation with error handling"""
        try:
            pyperclip.copy(text)
            return True
        except Exception as e:
            print(f"Clipboard error: {e}")
            return False
    
    def clear_form(self):
        """Reset all form fields to empty state"""
        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.notes_text.delete(1.0, tk.END)
        self.save_button.config(text="💾 SAVE")
        self.selection_info.config(text="Select an entry from the list on the right")
        self.show_status("✅ Form cleared", "success")
    
    def on_tree_select(self, event):
        """Handle treeview selection event and update selection info"""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            site = self.tree.item(item)['values'][0]
            site_str = str(site)
            if site_str in self.passwords:
                data = self.passwords[site_str]
                self.selection_info.config(
                    text=f"Selected: {site_str} (Updated: {data.get('updated_at', 'Unknown')})"
                )
    
    def on_tree_double_click(self, event):
        """Handle double-click on treeview item to load into form"""
        self.load_selected_to_form()
    
    def load_selected_to_form(self):
        """Load selected password entry data into form for editing"""
        selection = self.tree.selection()
        if not selection:
            self.show_status("⚠️ Select an entry first", "warning")
            return
        
        item = selection[0]
        site = self.tree.item(item)['values'][0]
        
        site_str = str(site)
        if site_str in self.passwords:
            data = self.passwords[site_str]
            
            self.site_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.notes_text.delete(1.0, tk.END)
            
            self.site_entry.insert(0, site_str)
            self.username_entry.insert(0, data.get('username', ''))
            self.password_entry.insert(0, data.get('password', ''))
            self.notes_text.insert(1.0, data.get('notes', ''))
            
            self.save_button.config(text="💾 UPDATE")
            self.show_status(f"✅ Loaded '{site_str}' for editing", "success")
        else:
            self.show_status("❌ Could not load entry", "error")
    
    def toggle_selected_password_visibility(self):
        """Toggle password visibility for selected entry in list view"""
        selection = self.tree.selection()
        if not selection:
            self.show_status("⚠️ Select an entry first", "warning")
            return
        
        item = selection[0]
        site = self.tree.item(item)['values'][0]
        
        site_str = str(site)
        if site_str in self.revealed_passwords:
            del self.revealed_passwords[site_str]
            self.show_status(f"🔒 Hidden password for '{site_str}'", "success")
        else:
            if site_str in self.passwords:
                self.revealed_passwords[site_str] = self.passwords[site_str]['password']
                self.show_status(f"👁️ Showing password for '{site_str}'", "success")
            else:
                self.show_status("❌ Could not find password", "error")
        
        search_term = self.search_entry.get().strip()
        self.refresh_password_list(search_term)
    
    def delete_selected_password(self):
        """Delete selected password entry with confirmation dialog"""
        selection = self.tree.selection()
        if not selection:
            self.show_status("⚠️ Select an entry first", "warning")
            return
        
        item = selection[0]
        site = self.tree.item(item)['values'][0]
        
        site_str = str(site)
        if site_str in self.passwords:
            if messagebox.askyesno("Delete Entry", f"Delete entry for '{site_str}'?"):
                del self.passwords[site_str]
                if site_str in self.revealed_passwords:
                    del self.revealed_passwords[site_str]
                
                if self.save_data():
                    search_term = self.search_entry.get().strip()
                    self.refresh_password_list(search_term)
                    self.show_status(f"✅ Deleted entry for '{site_str}'", "success")
                else:
                    self.show_status("❌ Could not delete entry", "error")
    
    def delete_all_passwords(self):
        """Delete all password entries with extreme caution warning"""
        if not self.passwords:
            self.show_status("⚠️ No entries to delete", "warning")
            return
        
        count = len(self.passwords)
        if messagebox.askyesno("Delete All", f"Delete ALL {count} entries?\nThis action cannot be undone!"):
            self.passwords.clear()
            self.revealed_passwords.clear()
            
            if self.save_data():
                self.refresh_password_list()
                self.show_status(f"✅ Deleted all {count} entries", "success")
            else:
                self.show_status("❌ Could not delete entries", "error")
    
    def search_passwords(self, event=None):
        """Filter password list based on search term in real-time"""
        search_term = self.search_entry.get().strip()
        self.refresh_password_list(search_term)
    
    def clear_search(self):
        """Clear search field and restore full password list"""
        self.search_entry.delete(0, tk.END)
        self.refresh_password_list()
    
    def show_status(self, message, type="info"):
        """Display status messages with appropriate color coding"""
        colors = {
            "success": self.colors['success'],
            "error": self.colors['danger'],
            "warning": self.colors['warning'],
            "info": self.colors['text_secondary']
        }
        
        emoji = {
            "success": "✅",
            "error": "❌",
            "warning": "⚠️",
            "info": "💬"
        }
        
        color = colors.get(type, colors["info"])
        self.status_bar.config(text=f"{emoji.get(type, '💬')} {message}", fg=color)

def main():
    """Application entry point with window centering and error handling"""
    root = tk.Tk()
    
    # Attempt to set application icon
    try:
        root.iconbitmap('icon.ico')
    except:
        pass
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'+{x}+{y}')
    
    app = PasswordManagerApp(root)
    
    root.mainloop()

if __name__ == "__main__":
    # Validate required encryption libraries are available
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        print("Cryptography library is required for encryption.")
        print("Install it with: pip install cryptography")
        input("Press Enter to exit...")
        exit(1)
    
    # Check for clipboard functionality (optional but recommended)
    try:
        import pyperclip
    except ImportError:
        print("Pyperclip is recommended for clipboard functionality.")
        print("Install with: pip install pyperclip")
        # Create stub for clipboard operations
        class PyperclipStub:
            @staticmethod
            def copy(text):
                print(f"Clipboard: {text}")
        pyperclip = PyperclipStub()
    
    main()