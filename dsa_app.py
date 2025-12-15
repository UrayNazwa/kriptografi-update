#!/usr/bin/env python3
import argparse
import base64
import os
import sys
import time
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature


def ensure_dir(path: str):
    if path and not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def generate_keys(out_dir: str, key_size: int = 2048) -> Tuple[str, str]:
    """
    Generate DSA private/public key pair and save to PEM files.
    Returns (private_key_path, public_key_path).
    """
    ensure_dir(out_dir)
    private_key = dsa.generate_private_key(key_size=key_size)
    public_key = private_key.public_key()

    priv_path = os.path.join(out_dir, "private_key.pem")
    pub_path = os.path.join(out_dir, "public_key.pem")

    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(pub_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return priv_path, pub_path


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def read_signature_file(signature_path: str) -> bytes:
    # Helper: baca signature dari file, otomatis deteksi Base64 atau bytes mentah
    with open(signature_path, "rb") as f:
        raw = f.read()
    # Coba deteksi Base64 (anggap konten teks ASCII/UTF-8)
    try:
        text = raw.decode("utf-8").strip()
        decoded = base64.b64decode(text, validate=True)
        return decoded
    except Exception:
        # Bukan Base64 yang valid, kembalikan bytes mentah
        return raw


def sign_data(data: bytes, private_key) -> Tuple[bytes, float]:
    """
    Sign data bytes using DSA + SHA256. Returns (signature_bytes, elapsed_ms).
    """
    start = time.perf_counter()
    signature = private_key.sign(data, hashes.SHA256())
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return signature, elapsed_ms


def verify_signature(signature: bytes, data: bytes, public_key) -> Tuple[bool, float]:
    """
    Verify signature using DSA + SHA256. Returns (is_valid, elapsed_ms).
    """
    start = time.perf_counter()
    try:
        public_key.verify(signature, data, hashes.SHA256())
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return True, elapsed_ms
    except InvalidSignature:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return False, elapsed_ms


def name_numbers(private_key_path: str, public_key_path: str, name: str, limit: int = 50, show_ascii: bool = False):
    priv = load_private_key(private_key_path)
    pub = load_public_key(public_key_path)
    data = name.encode("utf-8")

    # Tanda tangan ("enkripsi" sesuai label tugas)
    signature, enc_ms = sign_data(data, priv)
    # Verifikasi ("dekripsi" sesuai label tugas)
    is_valid, dec_ms = verify_signature(signature, data, pub)

    # Konversi signature bytes menjadi angka-angka desimal
    nums = list(signature)
    shown = nums[:limit]
    print(f"[NAMA] \"{name}\"")
    print(f"[ANGKA SIGNATURE DECIMAL] ({len(nums)} bytes, tampilkan {len(shown)}): {' '.join(str(n) for n in shown)}")
    print(f"[WAKTU] Enkripsi (sign): {enc_ms:.3f} ms | Dekripsi (verify): {dec_ms:.3f} ms")
    print(f"[VERIFIKASI] Valid: {is_valid}")

    # Tambahan: angka-angka ASCII dari nama (menggunakan kode karakter per huruf)
    if show_ascii:
        ascii_codes = [ord(ch) for ch in name]
        print(f"[ANGKA ASCII NAMA] ({len(ascii_codes)} chars): {' '.join(str(n) for n in ascii_codes)}")


def sign_message(private_key_path: str, message: str, out_signature_path: str, print_base64: bool = False):
    priv = load_private_key(private_key_path)
    data = message.encode("utf-8")
    signature, elapsed_ms = sign_data(data, priv)

    # Simpan sebagai Base64 (teks)
    sig_b64 = base64.b64encode(signature).decode("ascii")
    with open(out_signature_path, "w", encoding="utf-8") as f:
        f.write(sig_b64 + "\n")

    # Output bergaya enkripsi/ciphertext
    print(f"[ENKRIPSI] Waktu enkripsi (sign): {elapsed_ms:.3f} ms")
    print(f"[ENKRIPSI] Ukuran ciphertext (signature bytes): {len(signature)} bytes")
    print(f"[SIGN MESSAGE] Signature disimpan (Base64): {out_signature_path}")
    if print_base64:
        print(f"[SIGN MESSAGE] Signature (Base64): {sig_b64}")


def verify_message(public_key_path: str, message: str, signature_path: str):
    pub = load_public_key(public_key_path)
    data = message.encode("utf-8")
    signature = read_signature_file(signature_path)

    is_valid, elapsed_ms = verify_signature(signature, data, pub)
    # Output bergaya dekripsi
    print(f"[DEKRIPSI] Waktu dekripsi (verify): {elapsed_ms:.3f} ms")
    print(f"[VERIFY MESSAGE] Signature valid: {is_valid}")
    return is_valid


def sign_file(private_key_path: str, file_path: str, out_signature_path: str, print_base64: bool = False):
    priv = load_private_key(private_key_path)
    with open(file_path, "rb") as f:
        data = f.read()

    signature, elapsed_ms = sign_data(data, priv)

    # Simpan sebagai Base64 (teks)
    sig_b64 = base64.b64encode(signature).decode("ascii")
    with open(out_signature_path, "w", encoding="utf-8") as f:
        f.write(sig_b64 + "\n")

    print(f"[SIGN FILE] File: {file_path}")
    print(f"[ENKRIPSI] Waktu enkripsi (sign): {elapsed_ms:.3f} ms")
    print(f"[ENKRIPSI] Ukuran ciphertext (signature bytes): {len(signature)} bytes")
    print(f"[SIGN FILE] Signature disimpan (Base64): {out_signature_path}")
    if print_base64:
        print(f"[SIGN FILE] Signature (Base64): {sig_b64}")


def verify_file(public_key_path: str, file_path: str, signature_path: str):
    pub = load_public_key(public_key_path)
    with open(file_path, "rb") as f:
        data = f.read()
    signature = read_signature_file(signature_path)

    is_valid, elapsed_ms = verify_signature(signature, data, pub)
    print(f"[VERIFY FILE] File: {file_path}")
    print(f"[DEKRIPSI] Waktu dekripsi (verify): {elapsed_ms:.3f} ms")
    print(f"[VERIFY FILE] Signature valid: {is_valid}")
    return is_valid


def test_scenario():
    """
    Skenario uji:
    - Generate keys
    - Sign pesan asli, verify -> True
    - Modifikasi pesan, verify -> False
    """
    print("=== SKENARIO UJI: DSA SIGN/VERIFY ===")
    keys_dir = "keys"
    ensure_dir(keys_dir)
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path = os.path.join(keys_dir, "public_key.pem")

    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        print("[TEST] Generate keys terlebih dahulu...")
        generate_keys(keys_dir, key_size=2048)

    message = "Pesan rahasia untuk diuji"
    sig_path = "message.sig"

    print("\n[Test] Tanda tangani pesan asli...")
    sign_message(priv_path, message, sig_path)

    print("\n[Test] Verifikasi pesan asli (harus valid)...")
    valid_original = verify_message(pub_path, message, sig_path)

    print("\n[Test] Modifikasi pesan dan verifikasi (harus TIDAK valid)...")
    modified_message = message + "!"
    valid_modified = verify_message(pub_path, modified_message, sig_path)

    print("\n=== HASIL ===")
    print(f"Pesan asli valid?  {valid_original}")
    print(f"Pesan modifikasi valid?  {valid_modified}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Aplikasi tanda tangan digital menggunakan DSA (Digital Signature Algorithm)"
    )
    sub = parser.add_subparsers(dest="command")

    # gen-keys
    p_gen = sub.add_parser("gen-keys", help="Generate pasangan kunci DSA dan simpan ke folder")
    p_gen.add_argument("--out", "-o", default="keys", help="Folder output untuk kunci (default: keys)")
    p_gen.add_argument("--key-size", type=int, default=2048, choices=[1024, 2048, 3072],
                       help="Ukuran key DSA (default: 2048)")

    # sign-message
    p_sm = sub.add_parser("sign-message", help="Tanda tangani pesan teks")
    p_sm.add_argument("--key", "-k", required=True, help="Path private_key.pem")
    p_sm.add_argument("--message", "-m", required=True, help="Pesan teks untuk ditandatangani")
    p_sm.add_argument("--out", "-o", default="message.sig", help="Path file signature output (default: message.sig)")
    p_sm.add_argument("--print-base64", action="store_true", help="Cetak signature dalam Base64 ke console")

    # verify-message
    p_vm = sub.add_parser("verify-message", help="Verifikasi pesan teks dengan signature")
    p_vm.add_argument("--pub", "-p", required=True, help="Path public_key.pem")
    p_vm.add_argument("--message", "-m", required=True, help="Pesan teks yang ingin diverifikasi")
    p_vm.add_argument("--sig", "-s", required=True, help="Path file signature (.sig)")

    # sign-file
    p_sf = sub.add_parser("sign-file", help="Tanda tangani file")
    p_sf.add_argument("--key", "-k", required=True, help="Path private_key.pem")
    p_sf.add_argument("--in", "-i", dest="infile", required=True, help="Path file input yang ingin ditandatangani")
    p_sf.add_argument("--out", "-o", default="file.sig", help="Path file signature output (default: file.sig)")
    p_sf.add_argument("--print-base64", action="store_true", help="Cetak signature dalam Base64 ke console")

    # verify-file
    p_vf = sub.add_parser("verify-file", help="Verifikasi file dengan signature")
    p_vf.add_argument("--pub", "-p", required=True, help="Path public_key.pem")
    p_vf.add_argument("--in", "-i", dest="infile", required=True, help="Path file input yang ingin diverifikasi")
    p_vf.add_argument("--sig", "-s", required=True, help="Path file signature (.sig)")

    # name-numbers: masukkan nama -> keluarkan angka-angka dari signature
    p_nn = sub.add_parser("name-numbers", help="Masukkan nama -> keluarkan angka-angka signature dan hasil verifikasi")
    p_nn.add_argument("--key", "-k", required=True, help="Path private_key.pem")
    p_nn.add_argument("--pub", "-p", required=True, help="Path public_key.pem")
    p_nn.add_argument("--name", "-n", required=True, help="Nama yang akan diproses")
    p_nn.add_argument("--limit", type=int, default=50, help="Batas jumlah angka signature yang ditampilkan")
    p_nn.add_argument("--show-ascii", action="store_true", help="Tampilkan angka ASCII dari nama (kode karakter per huruf)")

    # encdec-name (enkripsi/dekripsi label untuk nama)
    p_edn = sub.add_parser("encdec-name", help="Masukkan nama untuk proses 'enkripsi' (sign) dan 'dekripsi' (verify)")
    p_edn.add_argument("--key", "-k", required=True, help="Path private_key.pem")
    p_edn.add_argument("--pub", "-p", required=True, help="Path public_key.pem")
    p_edn.add_argument("--name", "-n", required=True, help="Nama yang akan diproses")

    # test-scenario
    sub.add_parser("test-scenario", help="Jalankan skenario uji: pesan asli vs dimodifikasi")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "gen-keys":
        priv_path, pub_path = generate_keys(args.out, key_size=args.key_size)
        print(f"[GEN KEYS] Private key: {priv_path}")
        print(f"[GEN KEYS] Public key:  {pub_path}")

    elif args.command == "sign-message":
        sign_message(args.key, args.message, args.out, print_base64=args.print_base64)

    elif args.command == "verify-message":
        ok = verify_message(args.pub, args.message, args.sig)
        sys.exit(0 if ok else 1)

    elif args.command == "sign-file":
        sign_file(args.key, args.infile, args.out, print_base64=args.print_base64)

    elif args.command == "verify-file":
        ok = verify_file(args.pub, args.infile, args.sig)
        sys.exit(0 if ok else 1)

    elif args.command == "name-numbers":
        name_numbers(args.key, args.pub, args.name, limit=args.limit, show_ascii=args.show_ascii)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()