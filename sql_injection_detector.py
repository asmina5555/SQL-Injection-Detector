import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Initialize a session for HTTP requests
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# Function to get all forms from a URL
def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

# Function to extract form details
def get_form_details(form):
    """Extracts all possible useful information about an HTML `form`"""
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# Function to check if a response is vulnerable to SQL injection
def is_vulnerable(response):
    """Determines whether a page is SQL Injection vulnerable from its `response`"""
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

# Function to scan for SQL injection vulnerabilities
def scan_sql_injection(url, output_text):
    output_text.insert(tk.END, f"[*] Scanning URL: {url}\n")
    output_text.update_idletasks()

    # Test URL for SQL injection
    for c in "\"'":
        new_url = f"{url}{c}"
        output_text.insert(tk.END, f"[!] Trying {new_url}\n")
        output_text.update_idletasks()
        res = s.get(new_url)
        if is_vulnerable(res):
            output_text.insert(tk.END, f"[+] SQL Injection vulnerability detected, link: {new_url}\n")
            return

    # Test forms for SQL injection
    forms = get_all_forms(url)
    output_text.insert(tk.END, f"[+] Detected {len(forms)} forms on {url}.\n")
    output_text.update_idletasks()

    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            url_joined = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url_joined, data=data)
            elif form_details["method"] == "get":
                res = s.get(url_joined, params=data)
            if is_vulnerable(res):
                output_text.insert(tk.END, f"[+] SQL Injection vulnerability detected, link: {url_joined}\n")
                output_text.insert(tk.END, "[+] Form Details:\n")
                output_text.insert(tk.END, f"{form_details}\n")
                output_text.update_idletasks()
                break

    output_text.insert(tk.END, "[*] Scan completed.\n")
    output_text.update_idletasks()

# Tkinter GUI
class SQLInjectionScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Detector")
        self.root.geometry("600x400")

        # URL Input
        self.url_label = tk.Label(root, text="Enter URL to scan:", font=("Arial", 12))
        self.url_label.pack(pady=10)

        self.url_entry = tk.Entry(root, width=50, font=("Arial", 10))
        self.url_entry.pack(pady=5)

        # Scan Button
        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan, font=("Arial", 10))
        self.scan_button.pack(pady=10)

        # Output Text Area
        self.output_text = scrolledtext.ScrolledText(root, width=70, height=15, font=("Arial", 10))
        self.output_text.pack(pady=10)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to scan.")
            return

        self.output_text.delete(1.0, tk.END)  # Clear previous output
        self.output_text.insert(tk.END, "[*] Starting SQL Injection Scan...\n")
        self.output_text.update_idletasks()

        try:
            scan_sql_injection(url, self.output_text)
        except Exception as e:
            self.output_text.insert(tk.END, f"[-] An error occurred: {e}\n")
            self.output_text.update_idletasks()

# Main function to run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SQLInjectionScannerApp(root)
    root.mainloop()

        