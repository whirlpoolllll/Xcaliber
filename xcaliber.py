import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import random
import time
import requests # pip install requests
import nmap  # pip install python-nmap
import threading
import json

class XcaliberApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Xcaliber - Ethical Hacking Calibration Tool")
        self.root.geometry("700x800")

        # tabs
        self.notebook = ttk.Notebook(self.root)
        self.scan_tab = ttk.Frame(self.notebook)
        self.payload_tab = ttk.Frame(self.notebook)
        self.rate_tab = ttk.Frame(self.notebook)
        self.env_tab = ttk.Frame(self.notebook)
        self.burp_tab = ttk.Frame(self.notebook)
        self.metasploit_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.scan_tab, text="Scan Calibration")
        self.notebook.add(self.payload_tab, text="Payload Tuning")
        self.notebook.add(self.rate_tab, text="Rate Limiting")
        self.notebook.add(self.env_tab, text="Environment Testing")
        self.notebook.add(self.burp_tab, text="Burp Suite Integration")
        self.notebook.add(self.metasploit_tab, text="Metasploit Integration")

        self.notebook.pack(expand=1, fill="both")

        # Scan Calibration
        self.create_scan_tab()

        # Payload Tuning
        self.create_payload_tab()

        # Rate Limiting
        self.create_rate_tab()

        # Environment Testing
        self.create_env_tab()

        # Burp Suite Integration
        self.create_burp_tab()

        # Metasploit Integration
        self.create_metasploit_tab()

    def create_scan_tab(self):
        ttk.Label(self.scan_tab, text="Target IP/Range:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.target_ip = tk.StringVar(value="192.168.1.1")
        ttk.Entry(self.scan_tab, textvariable=self.target_ip).grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(self.scan_tab, text="Scan Type:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.scan_type = tk.StringVar(value="basic")
        ttk.Combobox(
            self.scan_tab, textvariable=self.scan_type,
            values=["basic", "intense", "stealth"]
        ).grid(row=1, column=1, padx=10, pady=5)

        ttk.Button(self.scan_tab, text="Run Scan", command=self.run_scan).grid(row=2, column=0, columnspan=2, pady=20)
        self.scan_output = tk.Text(self.scan_tab, height=15, width=80)
        self.scan_output.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    def create_payload_tab(self):
        ttk.Label(self.payload_tab, text="Payload Type:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.payload_type = tk.StringVar(value="sql_injection")
        ttk.Combobox(
            self.payload_tab, textvariable=self.payload_type,
            values=["sql_injection", "xss", "lfi"]
        ).grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(self.payload_tab, text="Custom Payload (optional):").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.custom_payload = tk.StringVar()
        ttk.Entry(self.payload_tab, textvariable=self.custom_payload).grid(row=1, column=1, padx=10, pady=5)

        ttk.Button(self.payload_tab, text="Test Payload", command=self.test_payload).grid(row=2, column=0, columnspan=2, pady=20)
        self.payload_output = tk.Text(self.payload_tab, height=15, width=80)
        self.payload_output.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    def create_rate_tab(self):
        ttk.Label(self.rate_tab, text="Target URL:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.target_url = tk.StringVar(value="http://example.com")
        ttk.Entry(self.rate_tab, textvariable=self.target_url).grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(self.rate_tab, text="Requests per Second:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.requests_per_second = tk.StringVar(value="10")
        ttk.Entry(self.rate_tab, textvariable=self.requests_per_second).grid(row=1, column=1, padx=10, pady=5)

        ttk.Button(self.rate_tab, text="Simulate Load", command=self.simulate_load).grid(row=2, column=0, columnspan=2, pady=20)
        self.rate_output = tk.Text(self.rate_tab, height=15, width=80)
        self.rate_output.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    def create_env_tab(self):
        ttk.Label(self.env_tab, text="Latency (ms):").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.latency = tk.StringVar(value="100")
        ttk.Entry(self.env_tab, textvariable=self.latency).grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(self.env_tab, text="Bandwidth (Mbps):").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.bandwidth = tk.StringVar(value="10")
        ttk.Entry(self.env_tab, textvariable=self.bandwidth).grid(row=1, column=1, padx=10, pady=5)

        ttk.Button(self.env_tab, text="Simulate Environment", command=self.simulate_environment).grid(row=2, column=0, columnspan=2, pady=20)
        self.env_output = tk.Text(self.env_tab, height=15, width=80)
        self.env_output.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    def create_burp_tab(self):
        ttk.Label(self.burp_tab, text="Burp Suite Target:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.burp_target = tk.StringVar(value="http://example.com")
        ttk.Entry(self.burp_tab, textvariable=self.burp_target).grid(row=0, column=1, padx=10, pady=5)

        ttk.Button(self.burp_tab, text="Scan with Burp Suite", command=self.scan_with_burp).grid(row=1, column=0, columnspan=2, pady=20)
        self.burp_output = tk.Text(self.burp_tab, height=15, width=80)
        self.burp_output.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

    def create_metasploit_tab(self):
        ttk.Label(self.metasploit_tab, text="Metasploit Target IP:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.metasploit_target = tk.StringVar(value="192.168.1.1")
        ttk.Entry(self.metasploit_tab, textvariable=self.metasploit_target).grid(row=0, column=1, padx=10, pady=5)

        ttk.Button(self.metasploit_tab, text="Run Metasploit Exploit", command=self.run_metasploit).grid(row=1, column=0, columnspan=2, pady=20)
        self.metasploit_output = tk.Text(self.metasploit_tab, height=15, width=80)
        self.metasploit_output.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

    def run_scan(self):
        def scan():
            target = self.target_ip.get()
            scan_type = self.scan_type.get()
            scanner = nmap.PortScanner()
            try:
                self.scan_output.insert(tk.END, f"Scanning {target} with {scan_type} mode...\n")
                if scan_type == "basic":
                    result = scanner.scan(target)
                elif scan_type == "intense":
                    result = scanner.scan(target, arguments="-T4 -A")
                elif scan_type == "stealth":
                    result = scanner.scan(target, arguments="-sS")
                self.scan_output.insert(tk.END, json.dumps(result, indent=4))
            except Exception as e:
                self.scan_output.insert(tk.END, f"Error: {e}\n")
        
        threading.Thread(target=scan, daemon=True).start()

    def test_payload(self):
        payload_type = self.payload_type.get()
        custom_payload = self.custom_payload.get()
        self.payload_output.insert(tk.END, f"Testing {payload_type} payload...\n")
        if custom_payload:
            self.payload_output.insert(tk.END, f"Custom payload: {custom_payload}\n")
        else:
            self.payload_output.insert(tk.END, f"Default payload: {payload_type}\n")

    def simulate_load(self):
        target = self.target_url.get()
        requests_per_second = int(self.requests_per_second.get())
        for _ in range(requests_per_second):
            try:
                response = requests.get(target)
                self.rate_output.insert(tk.END, f"Status Code: {response.status_code}\n")
            except requests.exceptions.RequestException as e:
                self.rate_output.insert(tk.END, f"Error: {e}\n")
            time.sleep(1)

    def simulate_environment(self):
        latency = int(self.latency.get())
        bandwidth = int(self.bandwidth.get())
        self.env_output.insert(tk.END, f"Simulating environment: Latency = {latency}ms, Bandwidth = {bandwidth}Mbps\n")

    def scan_with_burp(self):
        burp_url = "http://localhost:8080"  # burp suite default API URL
        target = self.burp_target.get()
        self.burp_output.insert(tk.END, f"Starting scan on {target} using Burp Suite...\n")
        try:
            response = requests.get(f"{burp_url}/v1/scan", params={"target": target})
            if response.status_code == 200:
                self.burp_output.insert(tk.END, "Burp Suite scan successful\n")
            else:
                self.burp_output.insert(tk.END, f"Burp Suite scan failed: {response.text}\n")
        except Exception as e:
            self.burp_output.insert(tk.END, f"Error: {e}\n")

    def run_metasploit(self):
        target = self.metasploit_target.get()
        self.metasploit_output.insert(tk.END, f"Running Metasploit exploit against {target}...\n")
        try:
            # example of running an exploit with RPC API
            msf_url = "http://localhost:3790"  # default metasploit RPC API
            session = requests.post(f"{msf_url}/api/login", data={"username": "msf", "password": "password"})
            if session.status_code == 200:
                self.metasploit_output.insert(tk.END, f"Session started successfully for {target}\n")
                # run some exploits or other Mmtasploit actions
            else:
                self.metasploit_output.insert(tk.END, f"Failed to authenticate with Metasploit\n")
        except Exception as e:
            self.metasploit_output.insert(tk.END, f"Error: {e}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = XcaliberApp(root)
    root.mainloop()
