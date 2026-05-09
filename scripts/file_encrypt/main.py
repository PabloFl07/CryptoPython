import argparse
import getpass
from pathlib import Path
from keys import FileSource, InvalidKeyError, KeyManager, PasswordSource
from run import Run
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM


class Commands:
    """
    Entry point after argument parsing. Retrieves the data and calls Run class to handle it.
    """

    @staticmethod
    def get_source(args):
        return (
            FileSource(Path(args.keyfile))
            if args.keyfile
            else PasswordSource(getpass.getpass("Provide a password: "))
        )

    @staticmethod
    def genkey(args):

        key_manager = KeyManager(args.path)

        key_manager.generate_key(force=args.force)
        return f"Key created successfully at `{key_manager.path}`"

    @staticmethod
    def encrypt(args):

        source = Commands.get_source(args)

        input_path = Path(args.file)

        if not input_path.exists():
            raise FileNotFoundError("File to encrypt not found")

        output_path = Path(args.output) if args.output else None

        cipher = (ChaCha20Poly1305, 2) if args.c else (AESGCM, 1)

        Run.encrypt(input_path, output_path, source, cipher)

    @staticmethod
    def decrypt(args):

        source = Commands.get_source(args)

        input_path = Path(args.file)
        output_path = Path(args.output) if args.output else None
        Run.decrypt(input_path, output_path, source)

    @staticmethod
    def verify(args):
        if Run.verify(Path(args.original), Path(args.decrypted), args.algorithm):
            print("Integrity verified: The files are identical.")
            return
        print("Integrity verification failed: The files differ.")

    @staticmethod
    def hash(args):
        return Run.hash(Path(args.file), args.algorithm)


def parse_args():
    parser = argparse.ArgumentParser(description="File Vault")

    sub = parser.add_subparsers(dest="command", required=True)

    # ==== GENKEY ==== #
    p = sub.add_parser("genkey")
    p.add_argument(
        "path",
        nargs="?",
        const=KeyManager._DEFAULT_KEY_FILE,
        default=None,  # VALUE IF NOT CALLED
        help="Where to generate the key ( current if empty )",
    )
    p.add_argument("--force", action="store_true")

    # ==== ENCRYPT ==== #
    p = sub.add_parser("encrypt")
    p.add_argument("file")
    p.add_argument("--output")
    p.add_argument(
        "-kf",
        "--keyfile",
        nargs="?",
        const=str(KeyManager._DEFAULT_KEY_FILE),  # VALUE IF CALLED ALONE (-kf)
        default=None,  # VALUE IF NOT CALLED
        help="Path to the key file",
    )

    # Mutually exclusive
    group = p.add_mutually_exclusive_group()
    group.add_argument("-a", action="store_true", help="Use AESGCM-256")
    group.add_argument("-c", action="store_true", help="Use ChaCha20-Poly1305")

    # ==== DECRYPT ==== #
    p = sub.add_parser("decrypt")
    p.add_argument("file")
    p.add_argument("--output")
    p.add_argument(
        "-kf",
        "--keyfile",
        nargs="?",
        const=str(KeyManager._DEFAULT_KEY_FILE),  # VALUE IF CALLED ALONE (-kf)
        default=None,  # VALUE IF NOT CALLED
        help="Path to the key file",
    )

    # ==== VERIFY ==== #
    p = sub.add_parser("verify")
    p.add_argument("original")
    p.add_argument("decrypted")
    p.add_argument("-a", "--algorithm", default="sha256")

    # ==== HASH ==== #
    p = sub.add_parser("hash")
    p.add_argument("file")
    p.add_argument("-a", "--algorithm", default="sha256")

    # Sets the target function of the command
    for cmd_name, cmd_func in [
        ("genkey", Commands.genkey),
        ("encrypt", Commands.encrypt),
        ("decrypt", Commands.decrypt),
        ("verify", Commands.verify),
        ("hash", Commands.hash),
    ]:
        sub.choices[cmd_name].set_defaults(func=cmd_func)

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        result = args.func(args)
        if result is not None:
            print(result)

    except KeyboardInterrupt:
        print("\nCanceled.")
    except (ValueError, FileNotFoundError, InvalidKeyError) as e:
        print(f"\nError: {e}")
        exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        exit(2)


if __name__ == "__main__":
    main()
