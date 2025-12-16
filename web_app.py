#!/usr/bin/env python3
import os
import base64
import time
from typing import Tuple, Optional

from flask import Flask, render_template, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature

APP_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(APP_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

app = Flask(__name__)

HISTORY_MAX = 50
HISTORY = []

@app.context_processor
def inject_history():
    return {"history": HISTORY}

def _record(result):
    try:
        section = result.get("section")
    except Exception:
        section = "unknown"
    summary = result.get("message") or result.get("error") or section
    HISTORY.insert(0, {"time": time.strftime('%H:%M:%S'), "section": section, "summary": summary, "data": result})
    del HISTORY[HISTORY_MAX:]

# ==== Helper: DSA basics ====
def ensure_dir(path: str):
    if path and not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def generate_keys(key_size: int = 2048) -> Tuple[str, str]:
    ensure_dir(KEYS_DIR)
    private_key = dsa.generate_private_key(key_size=key_size)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign_data(data: bytes, private_key) -> Tuple[bytes, float]:
    start = time.perf_counter()
    signature = private_key.sign(data, hashes.SHA256())
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return signature, elapsed_ms

def verify_signature(signature: bytes, data: bytes, public_key) -> Tuple[bool, float]:
    start = time.perf_counter()
    try:
        public_key.verify(signature, data, hashes.SHA256())
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return True, elapsed_ms
    except InvalidSignature:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return False, elapsed_ms

def detect_and_decode_signature(signature_text: str) -> bytes:
    s = (signature_text or "").strip()
    # Coba Base64 dengan validasi
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        pass
    # Perbaiki padding jika perlu
    try:
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        return base64.b64decode(s + pad)
    except Exception:
        # Fallback: sebagai bytes teks
        return s.encode("utf-8")

def bytes_to_decimal_string(b: bytes, limit: int = 50) -> str:
    nums = list(b)
    shown = nums[:limit]
    return " ".join(str(n) for n in shown)

# ==== Routes ====
@app.route("/", methods=["GET"])
def index():
    keys_exists = os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)
    show_history = request.args.get("show_history") == "1"
    return render_template("index.html", keys_exists=keys_exists, result=None, show_history=show_history)

def index():
    if request.method == "POST":
        message = request.form.get("message")

        if message:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("INSERT INTO history (message) VALUES (?)", (message,))
            conn.commit()
            conn.close()

        return redirect("/")

    return render_template("index.html")

@app.route("/gen-keys", methods=["POST"])
def route_gen_keys():
    key_size_str = request.form.get("key_size", "2048")
    try:
        key_size = int(key_size_str)
    except ValueError:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "gen-keys", "error": "Ukuran kunci tidak valid."})

    allowed_sizes = {1024, 2048, 3072}
    if key_size not in allowed_sizes:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "gen-keys", "error": "Ukuran kunci harus 1024, 2048, atau 3072."})

    generate_keys(key_size=key_size)
    result = {"section": "gen-keys", "key_size": key_size, "message": "Kunci berhasil dibuat."}
    _record(result)
    return render_template("index.html", keys_exists=True, result=result)

@app.route("/encdec-name", methods=["POST"])
def route_encdec_name():
    name = request.form.get("name", "").strip()
    limit = int(request.form.get("limit", "50"))
    show_ascii = bool(request.form.get("show_ascii"))

    if not name:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "encdec-name", "error": "Nama tidak boleh kosong."})

    if not _keys_ok():
        return render_template("index.html", keys_exists=False,
                               result={"section": "encdec-name", "error": "Kunci belum tersedia. Silakan Generate Keys."})

    priv = load_private_key(PRIVATE_KEY_PATH)
    pub = load_public_key(PUBLIC_KEY_PATH)
    data = name.encode("utf-8")

    signature, enc_ms = sign_data(data, priv)
    is_valid, dec_ms = verify_signature(signature, data, pub)

    result = {
        "section": "encdec-name",
        "name": name,
        "enc_ms": f"{enc_ms:.3f}",
        "dec_ms": f"{dec_ms:.3f}",
        "ciphertext_b64": base64.b64encode(signature).decode("ascii"),
        "ciphertext_size": len(signature),
        "decimal_preview": bytes_to_decimal_string(signature, limit),
        "verify_valid": is_valid,
        "show_ascii": show_ascii,
        "ascii_codes": [ord(ch) for ch in name] if show_ascii else [],
    }
    _record(result)
    return render_template("index.html", keys_exists=True, result=result)

@app.route("/sign-message", methods=["POST"])
def route_sign_message():
    message = request.form.get("message", "")
    if not message:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "sign-message", "error": "Pesan tidak boleh kosong."})

    if not _keys_ok():
        return render_template("index.html", keys_exists=False,
                               result={"section": "sign-message", "error": "Kunci belum tersedia. Silakan Generate Keys."})

    # Ambil kontrol baru
    limit = int(request.form.get("limit", "50"))
    show_ascii = bool(request.form.get("show_ascii"))

    priv = load_private_key(PRIVATE_KEY_PATH)
    data = message.encode("utf-8")
    signature, enc_ms = sign_data(data, priv)

    result = {
        "section": "sign-message",
        "message": message,
        "enc_ms": f"{enc_ms:.3f}",
        "ciphertext_b64": base64.b64encode(signature).decode("ascii"),
        "ciphertext_size": len(signature),
        "decimal_preview": bytes_to_decimal_string(signature, limit),
        "show_ascii": show_ascii,
        "ascii_codes": [ord(ch) for ch in message] if show_ascii else [],
    }
    _record(result)
    return render_template("index.html", keys_exists=True, result=result)

@app.route("/verify-message", methods=["POST"])
def route_verify_message():
    message = request.form.get("message", "")
    signature_text = request.form.get("signature_b64", "")
    if not message or not signature_text:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "verify-message", "error": "Pesan dan signature wajib diisi."})

    if not _keys_ok():
        return render_template("index.html", keys_exists=False,
                               result={"section": "verify-message", "error": "Kunci belum tersedia. Silakan Generate Keys."})

    pub = load_public_key(PUBLIC_KEY_PATH)
    data = message.encode("utf-8")

    # Coba deteksi Base64; jika tidak valid, gunakan bytes mentah dari teks
    decode_mode = "base64"
    try:
        sig_candidate = base64.b64decode(signature_text.strip(), validate=True)
        signature = sig_candidate
    except Exception:
        decode_mode = "raw"
        signature = signature_text.encode("utf-8")

    is_valid, dec_ms = verify_signature(signature, data, pub)

    result = {
        "section": "verify-message",
        "message": message,
        "dec_ms": f"{dec_ms:.3f}",
        "verify_valid": is_valid,
    }

    if not is_valid:
        reasons = []
        if decode_mode == "raw":
            reasons.append("Signature bukan Base64 valid; diproses sebagai bytes teks (format signature kemungkinan salah).")
        if len(signature) < 16:
            reasons.append(f"Ukuran signature sangat kecil ({len(signature)} bytes), kemungkinan data tidak lengkap atau tidak sesuai format.")
        reasons.append("Signature tidak cocok dengan pesan atau kunci publik (mungkin pesan diubah atau signature salah).")
        result["reasons"] = reasons

    _record(result)
    return render_template("index.html", keys_exists=True, result=result)

@app.route("/sign-file", methods=["POST"])
def route_sign_file():
    file = request.files.get("file")
    if not file or file.filename == "":
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "sign-file", "error": "Silakan unggah file untuk ditandatangani."})

    if not _keys_ok():
        return render_template("index.html", keys_exists=False,
                               result={"section": "sign-file", "error": "Kunci belum tersedia. Silakan Generate Keys."})

    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
        data = file.read()
        if not data:
            return render_template("index.html", keys_exists=_keys_ok(),
                                   result={"section": "sign-file", "error": "File kosong atau gagal dibaca."})

        signature, enc_ms = sign_data(data, priv)
    except Exception as e:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "sign-file", "error": f"Gagal menandatangani file: {type(e).__name__}: {e}"})

    result = {
        "section": "sign-file",
        "filename": file.filename,
        "enc_ms": f"{enc_ms:.3f}",
        "ciphertext_b64": base64.b64encode(signature).decode("ascii"),
        "ciphertext_size": len(signature),
    }
    _record(result)
    return render_template("index.html", keys_exists=True, result=result)

@app.route("/verify-file", methods=["POST"])
def route_verify_file():
    file = request.files.get("file")
    signature_text = request.form.get("signature_b64", "")
    if not file or file.filename == "" or not signature_text:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "verify-file", "error": "Unggah file dan isi signature Base64."})

    if not _keys_ok():
        return render_template("index.html", keys_exists=False,
                               result={"section": "verify-file", "error": "Kunci belum tersedia. Silakan Generate Keys."})

    try:
        pub = load_public_key(PUBLIC_KEY_PATH)
        data = file.read()
        if not data:
            return render_template("index.html", keys_exists=_keys_ok(),
                                   result={"section": "verify-file", "error": "File kosong atau gagal dibaca."})

        signature = detect_and_decode_signature(signature_text)
        is_valid, dec_ms = verify_signature(signature, data, pub)
    except Exception as e:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "verify-file", "error": f"Gagal verifikasi file: {type(e).__name__}: {e}"})

    result = {
        "section": "verify-file",
        "filename": file.filename,
        "dec_ms": f"{dec_ms:.3f}",
        "verify_valid": is_valid,
    }
    _record(result)
    return render_template("index.html", keys_exists=True, result=result)

def _keys_ok() -> bool:
    return os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)

def _hash_algo_from_name(name: str):
    n = (name or "").lower()
    if n == "sha256": return hashes.SHA256(), "SHA-256"
    if n == "sha384": return hashes.SHA384(), "SHA-384"
    if n == "sha512": return hashes.SHA512(), "SHA-512"
    # default
    return hashes.SHA256(), "SHA-256"

def hash_data(data: bytes, algo_name: str) -> Tuple[bytes, float, str]:
    algo, label = _hash_algo_from_name(algo_name)
    start = time.perf_counter()
    h = hashes.Hash(algo)
    h.update(data)
    digest = h.finalize()
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return digest, elapsed_ms, label

def hamming_distance_bytes(a: bytes, b: bytes) -> int:
    # Hitung jumlah bit berbeda (xor, lalu hitung bit '1')
    # Jika panjang berbeda, selisih sisanya dihitung sebagai berbeda.
    m = min(len(a), len(b))
    dist = sum((x ^ y).bit_count() for x, y in zip(a[:m], b[:m]))
    if len(a) > m:
        dist += sum(x.bit_count() for x in a[m:])
    elif len(b) > m:
        dist += sum(y.bit_count() for y in b[m:])
    return dist

def xor_hex(a: bytes, b: bytes) -> str:
    # XOR dua bytes, jika panjang berbeda, sisa yang lebih panjang dianggap XOR dengan 0
    m = min(len(a), len(b))
    xored = bytes((x ^ y) for x, y in zip(a[:m], b[:m]))
    if len(a) > m:
        xored += a[m:]
    elif len(b) > m:
        xored += b[m:]
    return xored.hex()

def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
        print("Database history.db berhasil dibuat!")
    else:
        print("Database sudah ada, tidak membuat baru.")

@app.route("/hash", methods=["POST"])
def route_hash():
    message = request.form.get("message", "")
    message2 = request.form.get("message2", "")
    algo = request.form.get("algo", "sha256")

    if not message:
        return render_template("index.html", keys_exists=_keys_ok(),
                               result={"section": "hash", "error": "Pesan wajib diisi untuk hashing."})

    digest, hash_ms, algo_label = hash_data(message.encode("utf-8"), algo)
    result = {
        "section": "hash",
        "algo_label": algo_label,
        "digest_hex": digest.hex(),
        "digest_bits": len(digest) * 8,
        "input_len": len(message.encode("utf-8")),
        "hash_ms": f"{hash_ms:.3f}",
        "message": message,
        "has_second": False,
    }

    if message2.strip():
        digest2, hash2_ms, _ = hash_data(message2.encode("utf-8"), algo)
        hamming_bits = hamming_distance_bytes(digest, digest2)
        percent_diff = (hamming_bits / (len(digest) * 8)) * 100 if len(digest) > 0 else 0.0
        result.update({
            "has_second": True,
            "message2": message2,
            "digest2_hex": digest2.hex(),
            "input2_len": len(message2.encode("utf-8")),
            "hash2_ms": f"{hash2_ms:.3f}",
            "hamming_bits": hamming_bits,
            "compare_equal": digest == digest2,
            "percent_diff": f"{percent_diff:.3f}",
            "xor_hex": xor_hex(digest, digest2),
        })

    _record(result)
    return render_template("index.html", keys_exists=_keys_ok(), result=result)

@app.route("/clear-history", methods=["POST"])
def route_clear_history():
    HISTORY.clear()
    keys_exists = _keys_ok()
    return render_template("index.html", keys_exists=keys_exists, result=None, show_history=False)

def history():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM history ORDER BY id DESC")
    data = c.fetchall()
    conn.close()

    return render_template("history.html", data=data)

# Blok eksekusi utama
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)