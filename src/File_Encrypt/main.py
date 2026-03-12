"""
- main function
- Argument parsing
- Entry Point for the script flow
    Using a function for every "Command"

# TODO:
    - Complete each Command argument parsing



    -genkey arg parsing and implemented
    -kf argument changed scope from global arg to encrypt / decrypt arg

"""

import argparse
import getpass
from pathlib import Path
from keys import KeyManager
from run import Run
from keys import PasswordSource, FileSource

# ───────────────────────────────────────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────────────────────────────────────


class Commands:
    """
    Entry point after argument parsing. Retrieves the data and calls Run class to handle it.
    """

    @staticmethod
    def genkey(args):

        key_manager = KeyManager(args.path)

        key_manager.generate_key(force=args.force)
        return f"Key created successfully at `{key_manager.path}`"

    # * Correctly parsers !
    @staticmethod
    def encrypt(args):

        if args.keyfile:
            source = FileSource(Path(args.keyfile))
        else:
            source = PasswordSource(getpass.getpass("Provide a password: "))

        input_path = Path(args.file)

        if not input_path.exists():
            raise FileNotFoundError("File to encrypt not found")

        output_path = Path(args.output) if args.output else None

        Run.encrypt(input_path, output_path, source, Run.get_cipher(args))

    @staticmethod
    def decrypt(args):
        if args.keyfile:
            source = FileSource(Path(args.keyfile))
        else:
            source = PasswordSource(getpass.getpass("Provide a password: "))

        in_path = Path(args.file)

        if not in_path.exists():
            raise FileNotFoundError("File to encrypt not found")

        out_path = Path(args.output) if args.output else None

        Run.decrypt(in_path, out_path, source)

    @staticmethod
    def verify():
        raise NotImplementedError()

    @staticmethod
    def hash():
        raise NotImplementedError()


# ───────────────────────────────────────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────────────────────────────────────


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
    for p, cmd in [
        ("genkey", Commands.genkey),
        ("encrypt", Commands.encrypt),
        ("decrypt", Commands.decrypt),
        ("verify", Commands.verify),
        ("hash", Commands.hash),
    ]:
        sub.choices[p].set_defaults(func=cmd)

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        result = args.func(args)

        if result:
            print(result)
    except KeyboardInterrupt:
        print("\nCancelado.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
