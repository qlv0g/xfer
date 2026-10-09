import os
import sys
import time
import hashlib
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from termcolor import colored

MiB = 1024 * 1024
READ_BLOCK = 64 * 1024
HDR = 5 + 16 + 8
CT_BLOCK = READ_BLOCK + 16
MIN_PLAIN = READ_BLOCK
MAX_PLAIN = 256 * MiB
ID_LEN = 64
BLOB_DIR = os.environ.get('XFER_BLOBS') or os.path.join(os.getcwd(), 'BLOBS')
VERBOSE = False
QUIET = False

def is_id(s):
    if len(s) != ID_LEN:
        return False
    return all(c in '0123456789abcdef' for c in s)

def wire_shape_ok(s):
    if s < HDR + CT_BLOCK:
        return False
    rem = s - HDR
    if rem % CT_BLOCK != 0:
        return False
    plain = (rem // CT_BLOCK) * READ_BLOCK
    if plain < MIN_PLAIN or plain > MAX_PLAIN:
        return False
    if plain > 16 * MiB:
        return plain % (16 * MiB) == 0
    if plain > MiB:
        return plain % MiB == 0
    return True

def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(READ_BLOCK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def log(msg, color="cyan"):
    if not QUIET:
        print(colored(msg, color))
        sys.stdout.flush()

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'xfer/1.0'

    def send_text(self, code, text, close=False):
        body = text.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        if close:
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def parse_id(self):
        parts = self.path.split('/')
        if len(parts) != 3 or parts[1] != 'b' or not is_id(parts[2]):
            return ''
        return parts[2]

    def do_PUT(self):
        blob_id = self.parse_id()
        if not blob_id:
            self.send_text(400, 'bad id', close=True)
            return
        try:
            clen = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            clen = 0
        if not wire_shape_ok(clen):
            self.send_text(413, 'bad blob shape/size', close=True)
            return
        tmp = os.path.join(BLOB_DIR, blob_id + '.part')
        h = hashlib.sha256()
        left = clen
        try:
            with open(tmp, 'wb') as f:
                while left > 0:
                    blk = self.rfile.read(min(READ_BLOCK, left))
                    if not blk:
                        raise Exception('short body')
                    f.write(blk)
                    h.update(blk)
                    left -= len(blk)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            self.send_text(400, 'short body', close=True)
            return
        if h.hexdigest() != blob_id:
            os.remove(tmp)
            self.send_text(422, 'hash mismatch')
            return
        dst = os.path.join(BLOB_DIR, blob_id)
        if os.path.isfile(dst):
            if hash_file(dst) == blob_id:
                os.remove(tmp)
                log(f"PUT {blob_id[:12]} {clen}B exists", "yellow")
                self.send_text(200, 'exists')
                return
            log(f"PUT {blob_id[:12]} quarantine of bad stored blob", "red")
        os.replace(tmp, dst)
        log(f"PUT {blob_id[:12]} {clen}B ok")
        self.send_text(201, blob_id)

    def do_GET(self):
        blob_id = self.parse_id()
        if not blob_id:
            self.send_text(400, 'bad id')
            return
        path = os.path.join(BLOB_DIR, blob_id)
        if not os.path.isfile(path):
            self.send_text(404, 'not found')
            return
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(size))
        self.send_header('ETag', f'"{blob_id}"')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            with open(path, 'rb') as f:
                while True:
                    blk = f.read(READ_BLOCK)
                    if not blk:
                        break
                    self.wfile.write(blk)
        except (BrokenPipeError, ConnectionResetError):
            return
        log(f"GET {blob_id[:12]} {size}B")

    def log_message(self, fmt, *args):
        if VERBOSE:
            log(f"{self.address_string()} {fmt % args}", "white")

def main():
    global VERBOSE, QUIET
    parser = argparse.ArgumentParser(description="xfer: тупой blob-store, ключей нет вообще")
    parser.add_argument('--host', default='0.0.0.0', help="адрес для слушания")
    parser.add_argument('--port', type=int, default=7777, help="порт")
    parser.add_argument('--blob-dir', default=BLOB_DIR, help="папка для блобов")
    parser.add_argument('--quiet', action='store_true', help="без логов запросов")
    parser.add_argument('--verbose', action='store_true', help="логировать адреса клиентов")
    args = parser.parse_args()
    QUIET = args.quiet
    VERBOSE = args.verbose

    os.makedirs(args.blob_dir, exist_ok=True)
    print(colored(f"xfer server: blobs in {args.blob_dir}", "cyan"))
    print(colored("No keys, no parsing, no content logs — только байты и sha256", "cyan"))
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(colored("\nInterrupted", "yellow"))
        sys.exit(130)

if __name__ == '__main__':
    main()

