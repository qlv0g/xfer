import os
import sys
import time
import struct
import hashlib
import argparse
import getpass
import shutil
import http.client
from urllib.parse import urlparse
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from termcolor import colored

MAGIC = b'XFER1'
SALT_LEN = 16
NONCE_PREFIX_LEN = 8
HDR = len(MAGIC) + SALT_LEN + NONCE_PREFIX_LEN
READ_BLOCK = 64 * 1024
CT_BLOCK = READ_BLOCK + 16
MAX_PLAIN = 256 * 1024 * 1024
MAX_NAME = 4096
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
TEMP_DIR = os.environ.get('XFER_TEMP') or os.path.join(os.getcwd(), 'TEMP')
os.makedirs(TEMP_DIR, exist_ok=True)

def derive_key(passphrase, salt):
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode('utf-8'))

def bucket_size(n):
    MiB = 1024 * 1024
    if n <= READ_BLOCK:
        return READ_BLOCK
    if n <= MiB:
        b = ((n + READ_BLOCK - 1) // READ_BLOCK) * READ_BLOCK
    elif n <= 16 * MiB:
        b = ((n + MiB - 1) // MiB) * MiB
    elif n <= MAX_PLAIN:
        b = ((n + 16 * MiB - 1) // (16 * MiB)) * (16 * MiB)
    else:
        raise Exception(f'файл слишком большой ({n} > {MAX_PLAIN})')
    if b > MAX_PLAIN:
        raise Exception(f'файл слишком большой ({n} > {MAX_PLAIN})')
    return b

def sanitize_name(name):
    name = name.replace('\\', '/').split('/')[-1]
    name = ''.join(c for c in name if c not in '<>:"|?*\x00').strip()
    if name in ('', '.', '..'):
        return ''
    return name

def is_id(s):
    if len(s) != 64:
        return False
    return all(c in '0123456789abcdef' for c in s)

def encrypt_file(src, dst, passphrase):
    size = os.path.getsize(src)
    name_b = sanitize_name(os.path.basename(src)).encode('utf-8')[:MAX_NAME]
    framing = struct.pack('<I', len(name_b)) + name_b + struct.pack('<Q', size)
    total = bucket_size(len(framing) + size)
    salt = os.urandom(SALT_LEN)
    npre = os.urandom(NONCE_PREFIX_LEN)
    chacha = ChaCha20Poly1305(derive_key(passphrase, salt))
    header = MAGIC + salt + npre
    h = hashlib.sha256()
    h.update(header)
    counter = 0
    written = 0
    with open(src, 'rb') as fin, open(dst, 'wb') as fout:
        fout.write(header)
        pending = framing
        while written < total:
            need = min(READ_BLOCK, total - written)
            buf = pending[:need]
            pending = pending[need:]
            if len(buf) < need:
                chunk = fin.read(need - len(buf))
                if chunk:
                    buf += chunk
            if len(buf) < need:
                buf += os.urandom(need - len(buf))
            nonce = npre + struct.pack('>I', counter)
            ad = MAGIC + struct.pack('>I', counter)
            ct = chacha.encrypt(nonce, buf, ad)
            fout.write(ct)
            h.update(ct)
            written += need
            counter += 1
    return h.hexdigest(), HDR + counter * CT_BLOCK

def decrypt_file(src, dst, passphrase, expect_id):
    h = hashlib.sha256()
    with open(src, 'rb') as f:
        header = f.read(HDR)
        if len(header) < HDR or header[:len(MAGIC)] != MAGIC:
            raise Exception('не XFER-данные (нет магии/заголовка)')
        h.update(header)
        salt = header[len(MAGIC):len(MAGIC) + SALT_LEN]
        npre = header[len(MAGIC) + SALT_LEN:]
        chacha = ChaCha20Poly1305(derive_key(passphrase, salt))
        counter = 0
        name = None
        size = None
        produced = 0
        out = None
        try:
            while True:
                data = f.read(CT_BLOCK)
                if not data:
                    break
                if len(data) != CT_BLOCK:
                    raise Exception('обрезанный блоб')
                h.update(data)
                nonce = npre + struct.pack('>I', counter)
                ad = MAGIC + struct.pack('>I', counter)
                pt = chacha.decrypt(nonce, data, ad)
                if counter == 0:
                    if len(pt) < 4:
                        raise Exception('битый заголовок')
                    (nlen,) = struct.unpack('<I', pt[:4])
                    if nlen > MAX_NAME or len(pt) < 4 + nlen + 8:
                        raise Exception('битый заголовок')
                    name = sanitize_name(pt[4:4 + nlen].decode('utf-8', 'replace'))
                    (size,) = struct.unpack('<Q', pt[4 + nlen:4 + nlen + 8])
                    if size > MAX_PLAIN:
                        raise Exception('заявленный размер больше лимита')
                    out = open(dst, 'wb')
                    chunk = pt[4 + nlen + 8:4 + nlen + 8 + size]
                    out.write(chunk)
                    produced = len(chunk)
                elif size is not None and produced < size:
                    take = min(READ_BLOCK, size - produced)
                    out.write(pt[:take])
                    produced += take
                counter += 1
        finally:
            if out is not None:
                out.close()
    if h.hexdigest() != expect_id:
        raise Exception(f'хеш не сходится: блоб подменён или повреждён')
    if name is None or size is None:
        raise Exception('пустой блоб')
    if produced != size:
        raise Exception('размер данных не совпал (обрезаны хвостовые чанки)')
    framing_len = 4 + len(name) + 8
    if counter * READ_BLOCK != bucket_size(framing_len + size):
        raise Exception('паддинг не в бакете — блоб подделан')
    return name, size

def get_pass(args, confirm=False):
    pw = args.passphrase or os.environ.get('XFER_PASS')
    if not pw:
        if not sys.stdin.isatty():
            print(colored("No passphrase: use --pass or XFER_PASS", "red"))
            sys.exit(2)
        pw = getpass.getpass('Passphrase: ')
        if not pw:
            print(colored("Empty passphrase", "red"))
            sys.exit(2)
        if confirm:
            pw2 = getpass.getpass('Repeat: ')
            if pw != pw2:
                print(colored("Passphrases don't match", "red"))
                sys.exit(2)
    return pw

def open_conn(server):
    u = urlparse(server)
    if u.scheme == 'https':
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=120)
    elif u.scheme == 'http':
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=120)
    else:
        raise Exception(f'неподдерживаемая схема: {u.scheme}')
    return conn, f"{u.scheme}://{u.netloc}"

def cmd_put(args):
    t0 = time.time()
    src = args.file
    if not os.path.isfile(src):
        print(colored(f"File not found: {src}", "red"))
        sys.exit(2)
    passphrase = get_pass(args, confirm=not args.passphrase)
    tmp = os.path.join(TEMP_DIR, f'put-{os.getpid()}.blob')
    try:
        print(colored(f"Encrypting {src} (scrypt N={SCRYPT_N}, ChaCha20-Poly1305)...", "cyan"))
        blob_id, blob_size = encrypt_file(src, tmp, passphrase)
        if os.path.getsize(tmp) != blob_size:
            raise Exception('internal: размер блоба не сошёлся')
        print(colored(f"Uploading {blob_size}B ...", "cyan"))
        conn, base = open_conn(args.server)
        conn.putrequest('PUT', f'/b/{blob_id}')
        conn.putheader('Content-Length', str(blob_size))
        conn.putheader('Content-Type', 'application/octet-stream')
        conn.endheaders()
        with open(tmp, 'rb') as f:
            while True:
                blk = f.read(READ_BLOCK)
                if not blk:
                    break
                conn.send(blk)
        resp = conn.getresponse()
        body = resp.read().decode('utf-8', 'replace')
        conn.close()
        if resp.status not in (200, 201):
            print(colored(f"Upload failed: {resp.status} {body}", "red"))
            sys.exit(1)
        token = f'{base}/b/{blob_id}'
        print(colored(f"Done: id {blob_id}, wire {blob_size}B, "
                      f"{round(time.time() - t0, 2)}s", "green"))
        print(colored(f"Token: {token}", "green"))
        print(colored("Передай токен и пароль получателю вне сервера "
                      "(мессенджер/QR) — сервер ключа не видит.", "yellow"))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

def cmd_get(args):
    t0 = time.time()
    target = args.target
    if target.startswith('http://') or target.startswith('https://'):
        u = urlparse(target)
        parts = u.path.split('/')
        if len(parts) != 3 or parts[1] != 'b' or not is_id(parts[2].lower()):
            print(colored(f"Bad token: {target}", "red"))
            sys.exit(2)
        blob_id = parts[2].lower()
        server = f"{u.scheme}://{u.netloc}"
    else:
        blob_id = target.lower()
        server = args.server
        if not is_id(blob_id):
            print(colored(f"Bad id: {target}", "red"))
            sys.exit(2)
        if not server:
            print(colored("Need --server for bare id", "red"))
            sys.exit(2)
    passphrase = get_pass(args)
    tmp = os.path.join(TEMP_DIR, f'get-{os.getpid()}.blob')
    out_tmp = os.path.join(TEMP_DIR, f'out-{os.getpid()}.bin')
    try:
        print(colored(f"Downloading {blob_id[:12]} ...", "cyan"))
        conn, _ = open_conn(server)
        conn.request('GET', f'/b/{blob_id}')
        resp = conn.getresponse()
        if resp.status != 200:
            body = resp.read().decode('utf-8', 'replace')
            conn.close()
            print(colored(f"Download failed: {resp.status} {body}", "red"))
            sys.exit(1)
        h = hashlib.sha256()
        got = 0
        with open(tmp, 'wb') as f:
            while True:
                blk = resp.read(READ_BLOCK)
                if not blk:
                    break
                f.write(blk)
                h.update(blk)
                got += len(blk)
        conn.close()
        if h.hexdigest() != blob_id:
            print(colored("Hash mismatch: блоб подменён на сервере, отказал.",
                          "red"))
            sys.exit(1)
        print(colored(f"Hash ok ({got}B), decrypting ...", "cyan"))
        try:
            name, size = decrypt_file(tmp, out_tmp, passphrase, blob_id)
        except InvalidTag:
            print(colored("Decrypt failed: неверный пароль или подделка данных",
                          "red"))
            sys.exit(1)
        final = args.out or name or f'restored-{blob_id[:8]}.bin'
        shutil.move(out_tmp, final)
        print(colored(f"Done: {final} ({size}B), {round(time.time() - t0, 2)}s",
                      "green"))
    finally:
        for p in (tmp, out_tmp):
            try:
                os.remove(p)
            except OSError:
                pass

def main():
    parser = argparse.ArgumentParser(
        description="xfer: анонимная передача, шифрование только на клиенте")
    sub = parser.add_subparsers(dest='cmd', required=True)
    p_put = sub.add_parser('put', help="зашифровать и залить файл")
    p_put.add_argument('file', help="файл для отправки")
    p_put.add_argument('--server', default='http://127.0.0.1:7777',
                       help="адрес сервера")
    p_put.add_argument('--pass', dest='passphrase', default='',
                       help="пароль (или XFER_PASS, или ввод с клавиатуры)")
    p_get = sub.add_parser('get', help="скачать и расшифровать")
    p_get.add_argument('target', help="token (URL) или голый id")
    p_get.add_argument('--server', default='',
                       help="адрес сервера, если передан голый id")
    p_get.add_argument('--pass', dest='passphrase', default='',
                       help="пароль (или XFER_PASS, или ввод с клавиатуры)")
    p_get.add_argument('-o', '--out', default='',
                       help="куда записать (по имени из шифра, если пусто)")
    args = parser.parse_args()
    try:
        if args.cmd == 'put':
            cmd_put(args)
        else:
            cmd_get(args)
    except KeyboardInterrupt:
        print(colored("\nInterrupted", "yellow"))
        sys.exit(130)
    except Exception as e:
        print(colored(f"Error: {e}", "red"))
        sys.exit(1)

if __name__ == '__main__':
    main()


