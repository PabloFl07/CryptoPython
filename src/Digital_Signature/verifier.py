import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
import utils
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ------------------------------------------------------------------ #
# Result type                                                          #
# ------------------------------------------------------------------ #

@dataclass
class VerificationResult:
    valid:   bool
    mode:    str
    details: dict = field(default_factory=dict)

    def __str__(self) -> str:
        status = "✓  VALID" if self.valid else "✗  INVALID"
        lines  = [f"[{self.mode}] {status}"]
        for k, v in self.details.items():
            if isinstance(v, dict):          # nested block (e.g. file_details in manifest)
                lines.append(f"  {k}:")
                for fk, fv in v.items():
                    lines.append(f"    {fk}: {fv}")
            else:
                lines.append(f"  {k}: {v}")
        return "\n".join(lines)


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _is_clearsign(path: Path) -> bool:
    """
    Detect a clearsign envelope by inspecting its first line,
    rather than relying on the file extension alone.
    Any valid UTF-8 text file could have a .txt extension, so
    checking the sentinel header is more robust.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            first_line = f.readline().strip()
        return first_line == "-----BEGIN SIGNED TEXT-----"
    except (UnicodeDecodeError, OSError):
        return False
    

def _verify_sig(pubkey: Ed25519PublicKey, sig_b64: str, message: bytes) -> bool:
    try:
        sig_bytes = utils.b64_decode(sig_b64)
        pubkey.verify(sig_bytes, message)
        return True
    except (InvalidSignature, binascii.Error, TypeError):
        return False



# ------------------------------------------------------------------ #
# Verifier                                                             #
# ------------------------------------------------------------------ #

class Verifier:
    """
    Verifies envelopes produced by Signer.

    Supported modes (auto-detected from the envelope file):
      - detached  : verifies signature + SHA-256 against the original file
      - inline    : verifies signature over embedded base64 data
      - manifest  : verifies signature over canonical hash list, re-hashes each file
      - clearsign : verifies signature over plain-text content using embedded public key

    Usage:
        result = Verifier().verify(Path("file.txt.sig.json"), original_file=Path("file.txt"))
        print(result)          # VerificationResult has a human-readable __str__
        assert result.valid
    """

    _MAX_FILE_SIZE = 500 * 1024 * 1024  # Definir el mismo límite que en Signer


    def verify(
        self,
        envelope_path: Path,
        original_file: Path = None,
        base_dir:      Path = None,
    ) -> VerificationResult:
        """
        Auto-detect the signing mode from the envelope and dispatch accordingly.

        Args:
            envelope_path: Path to the signed envelope (.sig.json, .jsig, .signed.txt).
            original_file: Required for detached mode — the original unsigned file.
            base_dir:      Base directory for resolving manifest paths.
                           Defaults to the directory containing the manifest file.
        """
        if not envelope_path.exists():
            raise FileNotFoundError(f"Envelope not found: {envelope_path}")

        # Clearsign envelopes are plain text — detect by content, not extension,
        # so that any UTF-8 text file with a different name is handled correctly.
        if _is_clearsign(envelope_path):
            return self._verify_clearsign(envelope_path)

        try:
            envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Could not parse envelope as JSON: {e}") from e

        mode = envelope.get("mode")
        match mode:
            case "detached":
                if original_file is None:
                    raise ValueError("Detached mode requires --file <original file>")
                return self._verify_detached(envelope, original_file)
            case "inline":
                return self._verify_inline(envelope)
            case "manifest":
                resolved_base = base_dir or envelope_path.parent
                return self._verify_manifest(envelope, resolved_base)
            case _:
                raise ValueError(f"Unknown or missing 'mode' in envelope: {mode!r}")

    # ------------------------------------------------------------------ #
    # Mode 1 — Detached                                                   #
    # ------------------------------------------------------------------ #

    def _verify_detached(self, envelope: dict, original_file: Path) -> VerificationResult:
        pubkey = utils.load_pem_public_key(envelope["public_key"])

        if original_file.stat().st_size > self._MAX_FILE_SIZE:
            raise ValueError(
                f"File too large for Ed25519 full-message signing. Max: {self._MAX_FILE_SIZE / (1024 * 1024):.0f} MB"
            )
        data   = original_file.read_bytes()

        sig_valid  = _verify_sig(pubkey, envelope["signature"], data)

        # Cross-check: recompute SHA-256 and compare to the value stored in the envelope.
        # Both the signature and the hash must match — a tampered file fails at least one.
        actual_hash = hashlib.sha256(data).hexdigest()
        hash_match  = actual_hash == envelope.get("sha256", "")

        return VerificationResult(
            valid=sig_valid and hash_match,
            mode="detached",
            details={
                "file":      str(original_file),
                "signature": "ok" if sig_valid  else "INVALID",
                "sha256":    "ok" if hash_match else f"MISMATCH — got {actual_hash}",
                "signer":    utils.key_fingerprint(pubkey),
                "timestamp": envelope.get("timestamp", "n/a"),
            },
        )

    # ------------------------------------------------------------------ #
    # Mode 2 — Inline                                                     #
    # ------------------------------------------------------------------ #

    def _verify_inline(self, envelope: dict) -> VerificationResult:
        pubkey = utils.load_pem_public_key(envelope["public_key"])
        data   = base64.b64decode(envelope["data"])

        sig_valid = _verify_sig(pubkey, envelope["signature"], data)

        return VerificationResult(
            valid=sig_valid,
            mode="inline",
            details={
                "filename":  envelope.get("filename", "n/a"),
                "signature": "ok" if sig_valid else "INVALID",
                "size":      f"{len(data):,} bytes",
                "signer":    utils.key_fingerprint(pubkey),
                "timestamp": envelope.get("timestamp", "n/a"),
            },
        )

    # ------------------------------------------------------------------ #
    # Mode 3 — Manifest                                                   #
    # ------------------------------------------------------------------ #

    def _verify_manifest(self, envelope: dict, base_dir: Path) -> VerificationResult:
        pubkey  = utils.load_pem_public_key(envelope["public_key"])
        entries = envelope["files"]

        # Reconstruct the canonical bytes that were signed.
        # Must use the exact same serialisation as sign_manifest: no spaces, keys sorted.
        canonical_bytes = json.dumps(
            entries, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        sig_valid = _verify_sig(pubkey, envelope["signature"], canonical_bytes)

        # Re-hash every file and compare to recorded hashes
        file_results: dict[str, str] = {}
        all_hashes_ok = True
        for entry in entries:
            path = (base_dir / entry["path"]).resolve()
            if not path.is_relative_to(base_dir.resolve()):
                file_results[entry["path"]] = "PATH TRAVERSAL DETECTADO"
                all_hashes_ok = False
                continue
            if not path.exists():
                file_results[entry["path"]] = "NOT FOUND"
                all_hashes_ok = False
                continue
            actual = utils.calculate_file_hash(path)
            if actual == entry["sha256"]:
                file_results[entry["path"]] = "ok"
            else:
                file_results[entry["path"]] = "HASH MISMATCH"
                all_hashes_ok = False

        files_ok = sum(1 for v in file_results.values() if v == "ok")

        return VerificationResult(
            valid=sig_valid and all_hashes_ok,
            mode="manifest",
            details={
                "signature":    "ok" if sig_valid else "INVALID",
                "files":        f"{files_ok}/{len(entries)} ok",
                "signer":       utils.key_fingerprint(pubkey),
                "timestamp":    envelope.get("timestamp", "n/a"),
                "file_details": file_results,
            },
        )

    # ------------------------------------------------------------------ #
    # Mode 4 — Clearsign                                                  #
    # ------------------------------------------------------------------ #

    def _verify_clearsign(self, envelope_path: Path) -> VerificationResult:
        """
        Parse a clearsign envelope and verify its embedded signature.

        Limitation: if the original content itself contains the literal string
        '\\n-----BEGIN ED25519 SIGNATURE-----\\n', parsing will fail. This is
        an inherent constraint of delimiter-based formats (same as PGP clearsign).
        """
        raw = envelope_path.read_text(encoding="utf-8")

        try:
            _, rest       = raw.split("-----BEGIN SIGNED TEXT-----\n", 1)
            content, rest = rest.split("\n-----BEGIN ED25519 SIGNATURE-----\n", 1)
            headers: dict[str, str] = {}
            for line in rest.splitlines():
                if line == "-----END ED25519 SIGNATURE-----":
                    break
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k] = v
        except ValueError as e:
            raise ValueError(f"Malformed clearsign envelope: {e}") from e

        sig_b64    = headers.get("Signature")
        pubkey_b64 = headers.get("Public key")
        timestamp  = headers.get("Timestamp", "n/a")

        if not sig_b64 or not pubkey_b64:
            raise ValueError(
                "Clearsign envelope is missing 'Signature' or 'Public key' header"
            )

        pubkey    = utils.load_raw_public_key(pubkey_b64)
        sig_valid = _verify_sig(pubkey, sig_b64, content.encode("utf-8"))

        return VerificationResult(
            valid=sig_valid,
            mode="clearsign",
            details={
                "signature":      "ok" if sig_valid else "INVALID",
                "signer":         utils.key_fingerprint(pubkey),
                "timestamp":      timestamp,
                "content_length": f"{len(content):,} chars",
            },
        )
