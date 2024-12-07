from http.server import SimpleHTTPRequestHandler, HTTPServer
import ssl

class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve pizza.txt without requiring authentication
        if self.path == "/pizza.txt":
            super().do_GET()
            return

        # For other files, require a valid secret key
        secret_key = "170"
        auth_header = self.headers.get("Authorization")
        if auth_header != f"Bearer {secret_key}":
            self.send_response(403)  # Forbidden
            self.end_headers()
            self.wfile.write(b"Forbidden: Invalid key")
            return

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
