import time
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import logging
import signal
from functools import partial
import re
import hashlib
import json

# Blockchain implementation for logging
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(previous_hash='1')  # Genesis block

    def create_block(self, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'previous_hash': previous_hash or self.hash(self.chain[-1]) if self.chain else '1'
        }
        self.chain.append(block)
        return block

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def add_log(self, action, ip_address):
        block = self.create_block()
        block['action'] = action
        block['ip_address'] = ip_address
        logging.info(f"Log added to blockchain: {block}")

# Extended list of malicious keywords or patterns to check for in requests
MALICIOUS_PATTERNS = [
    # XSS Attack Vectors
    r"<script.*?>.*?</script>",    # Script tags
    r"javascript:.*",              # JavaScript in URLs
    r"on\w+=",                      # Event handlers like onclick, onmouseover
    r"alert\(.*\)",                # JavaScript alert
    r"eval\(.*\)",                 # JavaScript eval
    r"document\.cookie",           # Accessing cookies
    r"document\.location",         # Redirecting
    r"window\.location",           # Redirecting
    r"iframe.*?src=.*?http",       # Embedding iframes with external sources
    r"data:text/html;base64,",      # Data URI

    # SQL Injection Patterns
    r"union\s+select",             # Union select SQL injection
    r"select\s+.*\s+from\s+information_schema.tables",  # SQL schema information
    r"select\s+.*\s+from\s+mysql.db",  # MySQL database access
    r"or\s+1=1",                   # Common SQL injection payload
    r"and\s+1=1",                  # SQL injection payload
    r"drop\s+table",               # SQL injection to drop tables
    r"insert\s+into\s+.*\s+values\s+\(.*\)", # SQL Injection inserting values
    r"update\s+.*\s+set\s+.*\s+where\s+.*", # SQL Injection updating records
    r"delete\s+from\s+.*\s+where\s+.*", # SQL Injection deleting records
    r"load_file\(",                # SQL Injection file loading
    r"outfile\s+.*",               # SQL Injection file writing
    r"exec\s+sp_executesql",       # SQL Server stored procedures
    r"sp_password",                # SQL Server password reset

    # Command Injection Patterns
    r"cmd\.exe\s+/c",              # Command execution on Windows
    r"powershell\s+[-]c",          # PowerShell command execution
    r"bash\s+-c",                  # Bash command execution
    r"nc\s+-e",                    # Netcat reverse shell
    r"wget\s+http",                # Downloading files from the web
    r"curl\s+http",                # Downloading files from the web
    r"php\s+shell_exec",           # PHP shell execution
    r"php\s+system",               # PHP system command execution
    r"php\s+passthru",             # PHP passthru command execution
    r"perl\s+-e",                  # Perl command execution
    r"python\s+-c",                # Python command execution
    r"exec\(.*\)",                # Execute command
    r"system\(.*\)",              # System command execution
    r"shell_exec\(.*\)",         # Shell execution
    r"sh\s+-c",                   # Shell command execution

    # File Inclusion Attacks
    r"\.\./",                      # Directory traversal
    r"\.\./\.\./",                # Multiple directory traversals
    r"php\s+include",             # PHP include function
    r"php\s+require",             # PHP require function
    r"include\s+.*",              # Generic include function
    r"require\s+.*",              # Generic require function
    r"file_get_contents\(.*\)",   # PHP file_get_contents function
    r"fopen\(.*\)",               # PHP fopen function

    # Remote Code Execution
    r"eval\(.*\)",                # PHP eval function
    r"assert\(.*\)",              # PHP assert function
    r"preg_replace\(.*\)",        # PHP preg_replace function
    r"file_get_contents\(.*\)",   # PHP file_get_contents function
    r"fopen\(.*\)",               # PHP fopen function

    # Ransomware and Backdoors
    r"ransomware",                # General keyword for ransomware
    r"backdoor",                  # Backdoor access
    r"remote\s+shell",            # Remote shell or backdoor
    r"reverse\s+shell",           # Reverse shell
    r"bind\s+shell",              # Bind shell

    # General Suspicious Patterns
    r"base64_decode",             # Base64 decoding
    r"phpinfo\(\)",              # PHP info function
    r"mysql_query\(.*\)",        # MySQL query execution
    r"mysqli_query\(.*\)",       # MySQLi query execution
    r"pdo_query\(.*\)",          # PDO query execution
    r"eval\(.*\)",               # PHP eval function
    r"base64_encode",            # Base64 encoding

    # Others
    r"remote\s+file\s+inclusion", # Remote File Inclusion
    r"local\s+file\s+inclusion",  # Local File Inclusion
    r"wget\s+http",               # Download files
    r"curl\s+http",               # Download files
    r"powershell\s+[-]e",         # PowerShell command
    r"bash\s+-c",                 # Bash command execution
    r"sh\s+-c",                   # Shell command execution

    # Directory Traversal
    r"\.\./\.\./\.\./\.\./",      # Multiple directory traversals
    r"etc/passwd",                # Access to /etc/passwd file
    r"proc/self/environ",         # Access to process environment
    r"../../../../../../etc/passwd", # Escalated directory traversal
    r"../../../../../../windows/win.ini", # Windows system directory

    # Suspicious URL Patterns
    r"ftp://",                    # FTP URL
    r"file://",                   # File URL
    r"http[s]?://\S+\.(exe|sh|bat|pl|py)", # Suspicious file extensions
    r"cmd.exe\s+/c\s+start\s+http", # Windows command to start HTTP
    r"telnet\s+\d+\.\d+\.\d+\.\d+", # Telnet connections
]

def contains_malicious_content(data):
    """Check if the request data contains any malicious patterns."""
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False

class RequestMonitor:
    def __init__(self, threshold=20, time_window=60, redirect_url=None, blockchain=None):
        self.request_count = defaultdict(int)
        self.request_times = defaultdict(list)
        self.blocked_ips = set()
        self.threshold = threshold
        self.time_window = time_window
        self.redirect_url = redirect_url
        self.blockchain = blockchain
        self.lock = threading.Lock()

    def add_request(self, client_address):
        current_time = time.time()
        with self.lock:
            if client_address in self.blocked_ips:
                return False

            self.request_times[client_address].append(current_time)
            self.request_count[client_address] += 1

            while self.request_times[client_address] and self.request_times[client_address][0] < current_time - self.time_window:
                self.request_times[client_address].pop(0)
                self.request_count[client_address] -= 1

            if self.request_count[client_address] > self.threshold:
                logging.warning(f"High request volume from {client_address}. Count: {self.request_count[client_address]}")
                if self.redirect_url:
                    if self.blockchain:
                        self.blockchain.add_log('Redirect', client_address)
                    return self.redirect_url
                else:
                    self.block_ip(client_address)
                    return False

            return True

    def block_ip(self, client_address):
        with self.lock:
            self.blocked_ips.add(client_address)
            logging.info(f"Blocked IP address: {client_address}")
            if self.blockchain:
                self.blockchain.add_log('Block', client_address)


class MonitoringHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, request_monitor=None, **kwargs):
        self.request_monitor = request_monitor
        super().__init__(*args, **kwargs)

    def do_GET(self):
        redirect_url = self.request_monitor.add_request(self.client_address[0])
        if redirect_url is True:
            self.send_error(403, "Your IP has been blocked due to high request volume.")
            return
        elif isinstance(redirect_url, str):
            self.send_response(302)  # Redirect response
            self.send_header('Location', redirect_url)
            self.end_headers()
            return

        if self.path == "/":
            self.serve_file("index.html", "text/html")
        elif self.path == "/stylesheet.css":
            self.serve_file("stylesheet.css", "text/css")
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        redirect_url = self.request_monitor.add_request(self.client_address[0])
        if redirect_url is True:
            self.send_error(403, "Your IP has been blocked due to high request volume.")
            return
        elif isinstance(redirect_url, str):
            self.send_response(302)  # Redirect response
            self.send_header('Location', redirect_url)
            self.end_headers()
            return

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        if contains_malicious_content(post_data):
            self.request_monitor.block_ip(self.client_address[0])
            self.send_error(403, "Malicious content detected. Your IP has been blocked.")
            return

        self.send_response(200)
        self.end_headers()

    def serve_file(self, file_path, content_type):
        try:
            with open(file_path, "r") as file:
                content = file.read()
            self.send_response(200)
            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        except FileNotFoundError:
            self.send_error(404, f"File Not Found: {file_path}")

def run_server(port, request_monitor, stop_event):
    handler = partial(MonitoringHandler, request_monitor=request_monitor)
    server = HTTPServer(('', port), handler)
    logging.info(f"Server running on port {port}")

    while not stop_event.is_set():
        try:
            server.handle_request()
        except Exception as e:
            logging.error(f"Server error: {e}")

    logging.info("Server is shutting down...")

if __name__ == "__main__":
    PORT = 8000
    REDIRECT_URL = "https://om1272006.github.io/Ddos-honypot/"  # Set your redirect URL here
    logging.basicConfig(level=logging.INFO)

    stop_event = threading.Event()

    def signal_handler(signal, frame):
        logging.info("Received shutdown signal.")
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    blockchain = Blockchain()
    monitor = RequestMonitor(threshold=20, time_window=60, redirect_url=REDIRECT_URL, blockchain=blockchain)
    server_thread = threading.Thread(target=run_server, args=(PORT, monitor, stop_event))
    server_thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Received KeyboardInterrupt. Exiting...")
        stop_event.set()

    server_thread.join()
    logging.info("Server has been stopped.")
