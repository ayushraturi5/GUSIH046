import time
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import logging
import signal
from functools import partial
import re

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
    def __init__(self, threshold=20, time_window=60):
        self.request_count = defaultdict(int)
        self.request_times = defaultdict(list)
        self.blocked_ips = set()
        self.threshold = threshold
        self.time_window = time_window
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
                self.block_ip(client_address)
                return False

            return True

    def block_ip(self, client_address):
        with self.lock:
            self.blocked_ips.add(client_address)
            logging.info(f"Blocked IP address: {client_address}")


class MonitoringHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, request_monitor=None, **kwargs):
        self.request_monitor = request_monitor
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if not self.request_monitor.add_request(self.client_address[0]):
            self.send_error(403, "Your IP has been blocked due to high request volume.")
            return

        if self.path == "/":
            # Serve the index.html file
            self.serve_file("index.html", "text/html")
        elif self.path == "/stylesheet.css":
            # Serve the stylesheet.css file
            self.serve_file("stylesheet.css", "text/css")
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        if not self.request_monitor.add_request(self.client_address[0]):
            self.send_error(403, "Your IP has been blocked due to high request volume.")
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        if contains_malicious_content(post_data):
            self.request_monitor.block_ip(self.client_address[0])
            self.send_error(403, "Malicious content detected. Your IP has been blocked.")
            return

        self.send_response(200)
        self.end_headers
