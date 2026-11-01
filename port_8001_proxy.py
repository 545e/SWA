"""
Transparent port forwarder/proxy from 8001 -> 8000
Ensures users accessing http://127.0.0.1:8001 see the live Generation 2 platform on port 8000.
"""
import sys
import http.server
import urllib.request
import urllib.error

TARGET_PORT = 8000
LISTEN_PORT = 8001

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Quiet logging

    def do_GET(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def do_OPTIONS(self):
        self._proxy()

    def _proxy(self):
        target_url = f"http://127.0.0.1:{TARGET_PORT}{self.path}"
        
        # Read request body if present
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        req_headers = {}
        for k, v in self.headers.items():
            if k.lower() not in ('host', 'content-length'):
                req_headers[k] = v

        req = urllib.request.Request(target_url, data=body, headers=req_headers, method=self.command)

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                self.send_response(resp.status)
                for header, val in resp.getheaders():
                    if header.lower() not in ('transfer-encoding', 'connection'):
                        self.send_header(header, val)
                self.end_headers()
                self.wfile.write(resp.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for header, val in e.headers.items():
                if header.lower() not in ('transfer-encoding', 'connection'):
                    self.send_header(header, val)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Proxy Error: {e}".encode())

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), ProxyHandler)
    print(f"Proxy listening on 0.0.0.0:{LISTEN_PORT} -> http://127.0.0.1:{TARGET_PORT}")
    server.serve_forever()
