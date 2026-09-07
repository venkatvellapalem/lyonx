"""Decoder — encode/decode data like Burp Decoder.

CLI tool for encoding, decoding, hashing, and transforming data.
Zero dependencies (stdlib only).

Usage:
    from hunter.core.decoder import Decoder
    
    d = Decoder()
    d.encode("hello", "base64")        # "aGVsbG8="
    d.decode("aGVsbG8=", "base64")     # "hello"
    d.hash("password", "md5")           # "5f4dcc3b5aa765d61d8327deb882cf99"
    d.transform("hello", "url_encode")  # "hello"
"""
import base64
import hashlib
import html
import urllib.parse
import json
import re
import binascii
from typing import Optional


class Decoder:
    """Data encoder/decoder — like Burp Decoder.
    
    Supported encodings:
        base64, base32, base16, url, html, hex, binary, unicode
        
    Supported hashes:
        md5, sha1, sha256, sha512
        
    Supported transforms:
        url_encode, url_decode, html_encode, html_decode,
        double_url_encode, unicode_encode, hex_encode
    """

    ENCODINGS = ["base64", "base32", "base16", "url", "html", "hex", "binary", "unicode"]
    HASHES = ["md5", "sha1", "sha256", "sha512", "sha384", "sha224"]
    TRANSFORMS = ["url_encode", "url_decode", "html_encode", "html_decode",
                  "double_url_encode", "unicode_encode", "hex_encode", "hex_decode",
                  "upper", "lower", "reverse", "strip"]

    def encode(self, data: str, encoding: str) -> str:
        """Encode data."""
        encoding = encoding.lower()

        if encoding == "base64":
            return base64.b64encode(data.encode()).decode()
        elif encoding == "base32":
            return base64.b32encode(data.encode()).decode()
        elif encoding == "base16" or encoding == "hex":
            return data.encode().hex()
        elif encoding == "url":
            return urllib.parse.quote(data, safe="")
        elif encoding == "html":
            return html.escape(data)
        elif encoding == "binary":
            return " ".join(format(b, "08b") for b in data.encode())
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in data)
        else:
            return f"Unknown encoding: {encoding}"

    def decode(self, data: str, encoding: str) -> str:
        """Decode data."""
        encoding = encoding.lower()

        if encoding == "base64":
            return base64.b64decode(data).decode(errors="ignore")
        elif encoding == "base32":
            return base64.b32decode(data).decode(errors="ignore")
        elif encoding == "base16" or encoding == "hex":
            return bytes.fromhex(data).decode(errors="ignore")
        elif encoding == "url":
            return urllib.parse.unquote(data)
        elif encoding == "html":
            return html.unescape(data)
        elif encoding == "binary":
            return "".join(chr(int(b, 2)) for b in data.split())
        elif encoding == "unicode":
            return data.encode().decode("unicode_escape")
        else:
            return f"Unknown encoding: {encoding}"

    def hash(self, data: str, algorithm: str) -> str:
        """Hash data."""
        algorithm = algorithm.lower()
        data_bytes = data.encode()

        if algorithm == "md5":
            return hashlib.md5(data_bytes).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(data_bytes).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(data_bytes).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(data_bytes).hexdigest()
        elif algorithm == "sha384":
            return hashlib.sha384(data_bytes).hexdigest()
        elif algorithm == "sha224":
            return hashlib.sha224(data_bytes).hexdigest()
        else:
            return f"Unknown algorithm: {algorithm}"

    def transform(self, data: str, transform: str) -> str:
        """Apply a transformation."""
        transform = transform.lower()

        if transform == "url_encode":
            return urllib.parse.quote(data, safe="")
        elif transform == "url_decode":
            return urllib.parse.unquote(data)
        elif transform == "html_encode":
            return html.escape(data)
        elif transform == "html_decode":
            return html.unescape(data)
        elif transform == "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(data, safe=""), safe="")
        elif transform == "unicode_encode":
            return "".join(f"%u{ord(c):04x}" for c in data)
        elif transform == "hex_encode":
            return data.encode().hex()
        elif transform == "hex_decode":
            return bytes.fromhex(data.replace(" ", "")).decode(errors="ignore")
        elif transform == "upper":
            return data.upper()
        elif transform == "lower":
            return data.lower()
        elif transform == "reverse":
            return data[::-1]
        elif transform == "strip":
            return data.strip()
        else:
            return f"Unknown transform: {transform}"

    def detect(self, data: str) -> list[str]:
        """Detect what encoding/hash a string might be.
        
        Returns list of possible encodings.
        """
        possible = []

        # Base64
        if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) % 4 == 0:
            try:
                decoded = base64.b64decode(data)
                if decoded.isascii() or len(decoded) > 0:
                    possible.append("base64")
            except:
                pass

        # Hex
        if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
            possible.append("hex")

        # URL encoded
        if '%' in data and re.search(r'%[0-9a-fA-F]{2}', data):
            possible.append("url")

        # HTML encoded
        if '&' in data and (';' in data) and re.search(r'&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;', data):
            possible.append("html")

        # Hash lengths
        if re.match(r'^[0-9a-f]+$', data):
            if len(data) == 32:
                possible.append("md5")
            elif len(data) == 40:
                possible.append("sha1")
            elif len(data) == 64:
                possible.append("sha256")
            elif len(data) == 128:
                possible.append("sha512")

        # JWT
        if data.count('.') == 2 and re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$', data):
            possible.append("jwt")

        # IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', data):
            possible.append("ipv4")

        return possible

    def jwt_decode(self, token: str) -> dict:
        """Decode a JWT token (without verification)."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}

            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            signature = parts[2]

            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "algorithm": header.get("alg", "unknown"),
            }
        except Exception as e:
            return {"error": str(e)}

    def all_encode(self, data: str) -> dict:
        """Encode data with all available encodings."""
        return {enc: self.encode(data, enc) for enc in self.ENCODINGS}

    def all_hash(self, data: str) -> dict:
        """Hash data with all available algorithms."""
        return {h: self.hash(data, h) for h in self.HASHES}
