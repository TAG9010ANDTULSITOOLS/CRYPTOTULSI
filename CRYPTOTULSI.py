# CRYPTOTULSI - Freedom First. Surveillance Last. Humanity Rebuilt.
# Full Project: Dark Mode, VPN Mesh, Mining, Blockchain, P2P, TULSI BLIND MODE

import os
import hashlib
import random
import threading
import time
import socket
import pickle
import socks
import ssl
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import zipfile
from ecdsa import SigningKey, SECP256k1

# Wallet generation
def generate_wallet(password: str):
    seed = hashlib.sha256(password.encode()).hexdigest()
    sk = SigningKey.from_string(bytes.fromhex(seed[:64]), curve=SECP256k1)
    vk = sk.verifying_key
    return sk, vk

# Blockchain structures
class Block:
    def __init__(self, previous_hash, transactions, nonce=0):
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.nonce = nonce

    def hash_block(self):
        block_contents = str(self.previous_hash) + str(self.transactions) + str(self.nonce)
        return hashlib.sha256(block_contents.encode()).hexdigest()

# Initialize blockchain ledger
blockchain = []
# Networking settings
PEER_NODES = []
LISTEN_PORT = random.randint(10000, 60000)
VPN_NODES = []

# SSL Context for encrypted P2P
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Mining control
mining = False

# Mining function
def mine_block(previous_hash, transactions):
    nonce = 0
    while True:
        block = Block(previous_hash, transactions, nonce)
        if block.hash_block().startswith('0000'):
            return block
        nonce += 1

# Start mining
def start_mining(wallet_address):
    global mining
    previous_hash = blockchain[-1].hash_block() if blockchain else '0' * 64
    while mining:
        reward_transaction = {'to': wallet_address, 'amount': 1}
        new_block = mine_block(previous_hash, [reward_transaction])
        blockchain.append(new_block)
        broadcast_block(new_block)
        previous_hash = new_block.hash_block()
        time.sleep(1)

# Networking server for P2P
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket = ssl_context.wrap_socket(server_socket, server_side=True)
    server_socket.bind(('0.0.0.0', LISTEN_PORT))
    server_socket.listen(5)
    while True:
        client_socket, addr = server_socket.accept()
        data = client_socket.recv(4096)
        try:
            incoming = pickle.loads(data)
            if isinstance(incoming, Block):
                handle_incoming_block(incoming)
        except:
            pass
        client_socket.close()

# Handle incoming block
def handle_incoming_block(block):
    if blockchain:
        if blockchain[-1].hash_block() == block.previous_hash:
            blockchain.append(block)
    else:
        blockchain.append(block)

# Broadcast block to peers
def broadcast_block(block):
    for peer in PEER_NODES:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            secure_sock = ssl_context.wrap_socket(sock, server_hostname=peer['ip'])
            secure_sock.connect((peer['ip'], peer['port']))
            secure_sock.send(pickle.dumps(block))
            secure_sock.close()
        except:
            pass

# Dynamic VPN proxy (multi-hop routing)
def start_dynamic_vpn_proxy(hops=3):
    if len(VPN_NODES) < hops:
        return
    selected_nodes = random.sample(VPN_NODES, hops)
    try:
        current_sock = socks.socksocket()
        first_node = selected_nodes[0]
        current_sock.set_proxy(socks.SOCKS5, first_node['ip'], first_node['port'])
        for next_node in selected_nodes[1:]:
            temp_sock = socks.socksocket()
            temp_sock.set_proxy(socks.SOCKS5, next_node['ip'], next_node['port'])
            temp_sock.connect(("example.com", 80))
            temp_sock.close()
    except:
        pass
# Theme definitions
DARK_THEME = {"bg": "#121212", "fg": "#ffffff", "button_bg": "#333333", "entry_bg": "#1e1e1e", "entry_fg": "#ffffff"}
LIGHT_THEME = {"bg": "#f0f0f0", "fg": "#000000", "button_bg": "#e0e0e0", "entry_bg": "#ffffff", "entry_fg": "#000000"}
current_theme = DARK_THEME

def apply_theme(window):
    window.configure(bg=current_theme["bg"])
    for widget in window.winfo_children():
        if isinstance(widget, (tk.Label, tk.Listbox)):
            widget.configure(bg=current_theme["bg"], fg=current_theme["fg"])
        elif isinstance(widget, (tk.Entry, tk.Text)):
            widget.configure(bg=current_theme["entry_bg"], fg=current_theme["entry_fg"], insertbackground=current_theme["entry_fg"])
        elif isinstance(widget, (tk.Button, tk.Checkbutton)):
            widget.configure(bg=current_theme["button_bg"], fg=current_theme["fg"], activebackground=current_theme["bg"])

# GUI system
def start_gui():
    def create_wallet():
        password = password_entry.get()
        global sk, vk, wallet_address
        sk, vk = generate_wallet(password)
        wallet_address = hashlib.sha256(vk.to_string()).hexdigest()
        wallet_label.config(text=f"Wallet: {wallet_address}")

    def start_mining_action():
        global mining
        mining = True
        threading.Thread(target=start_mining, args=(wallet_address,)).start()

    def stop_mining_action():
        global mining
        mining = False

    def add_peer():
        peer = peer_entry.get()
        if peer:
            ip, port = peer.split(':')
            PEER_NODES.append({'ip': ip, 'port': int(port)})
            peer_list.insert(tk.END, peer)

    def add_vpn():
        vpn = vpn_entry.get()
        if vpn:
            ip, port = vpn.split(':')
            VPN_NODES.append({'ip': ip, 'port': int(port)})
            vpn_list.insert(tk.END, vpn)

    def show_balance():
        balance = sum(tx['amount'] for block in blockchain for tx in block.transactions if tx['to'] == wallet_address)
        messagebox.showinfo("Wallet Balance", f"Your balance: {balance} CRYPTOTULSI")
    def view_code():
        code_window = tk.Toplevel(root)
        code_window.title("CRYPTOTULSI SOURCE CODE")
        code_area = scrolledtext.ScrolledText(code_window, wrap=tk.WORD)
        code_area.pack(fill=tk.BOTH, expand=True)
        try:
            with open(__file__, 'r') as f:
                code_area.insert(tk.END, f.read())
        except:
            code_area.insert(tk.END, "Source code unavailable.")
        apply_theme(code_window)

        # --- Add TULSI BLIND MODE Button ---
        def tulsi_blind_mode():
            blind_window = tk.Toplevel(code_window)
            blind_window.title("TULSI IN BLIND MODE")
            blind_area = scrolledtext.ScrolledText(blind_window, wrap=tk.WORD)
            blind_area.pack(fill=tk.BOTH, expand=True)
            apply_theme(blind_window)
            original_code = code_area.get("1.0", tk.END)
            blind_area.insert(tk.END, original_code)

            # Save original for Undo
            saved_original = original_code

            # Restrict keys: Allow backspace and symbols only
            allowed_chars = set('":;(){}[]')

            def on_key_press(event):
                if event.keysym == "BackSpace":
                    return
                elif event.char in allowed_chars:
                    return
                else:
                    return "break"

            blind_area.bind("<KeyPress>", on_key_press)

            # Syntax Error Check
            def check_errors():
                try:
                    code_to_check = blind_area.get("1.0", tk.END)
                    compile(code_to_check, '<string>', 'exec')
                    blind_window.title("TULSI IN BLIND MODE - Syntax OK")
                except Exception as e:
                    blind_window.title(f"TULSI IN BLIND MODE - Syntax Error: {e}")

            blind_area.bind("<KeyRelease>", lambda e: check_errors())

            # Undo button
            def undo_reset():
                blind_area.delete("1.0", tk.END)
                blind_area.insert(tk.END, saved_original)

            tk.Button(blind_window, text="UNDO", command=undo_reset).pack()

        tk.Button(code_window, text="TULSI IN BLIND MODE", command=tulsi_blind_mode).pack()
    def package_app():
        folder_to_package = filedialog.askdirectory(title="Select CRYPTOTULSI Folder")
        if folder_to_package:
            output_zip = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("Zip files", "*.zip")])
            if output_zip:
                package_cryptotulsi(folder_to_package, output_zip)
                messagebox.showinfo("Packager", f"CRYPTOTULSI packaged as {output_zip}")

    def toggle_theme():
        global current_theme
        if current_theme == DARK_THEME:
            current_theme = LIGHT_THEME
        else:
            current_theme = DARK_THEME
        apply_theme(root)

    # --- GUI Layout ---
    root = tk.Tk()
    root.title("CRYPTOTULSI GUI")

    wallet_label = tk.Label(root, text="Wallet: Not created")
    wallet_label.pack()

    password_entry = tk.Entry(root, show='*')
    password_entry.pack()

    tk.Button(root, text="Create Wallet", command=create_wallet).pack()
    tk.Button(root, text="Start Mining", command=start_mining_action).pack()
    tk.Button(root, text="Stop Mining", command=stop_mining_action).pack()

    peer_entry = tk.Entry(root)
    peer_entry.pack()
    tk.Button(root, text="Add Peer", command=add_peer).pack()
    peer_list = tk.Listbox(root)
    peer_list.pack()

    vpn_entry = tk.Entry(root)
    vpn_entry.pack()
    tk.Button(root, text="Add VPN Node", command=add_vpn).pack()
    vpn_list = tk.Listbox(root)
    vpn_list.pack()

    tk.Button(root, text="View Wallet Balance", command=show_balance).pack()
    tk.Button(root, text="View Program Source Code", command=view_code).pack()
    tk.Button(root, text="Package App for Portable Use", command=package_app).pack()
    tk.Button(root, text="Toggle Light/Dark Theme", command=toggle_theme).pack()

    apply_theme(root)
    root.mainloop()

# --- Utility: Portable Packager ---
def package_cryptotulsi(source_folder, output_zip, password=None):
    launcher_path = os.path.join(source_folder, "launch_cryptotulsi.bat")
    with open(launcher_path, "w") as f:
        f.write("@echo off\npython CRYPTOTULSI.py\npause\n")
    zipf = zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED)
    for foldername, subfolders, filenames in os.walk(source_folder):
        for filename in filenames:
            filepath = os.path.join(foldername, filename)
            arcname = os.path.relpath(filepath, source_folder)
            zipf.write(filepath, arcname)
    zipf.close()

# --- Main Entry ---
if __name__ == "__main__":
    sk = None
    vk = None
    wallet_address = None

    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    start_gui()
