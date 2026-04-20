
import argparse
from keys import KeyManager
from signer import Signer
from pathlib import Path
class Commands:
    """
    Entry point after argument parsing. Retrieves the data and calls Run class to handle it.
    """
    @staticmethod
    def genkey(args):
        
        manager = KeyManager(args.path)

        manager.generate_key()
        return f"Key created successfully at `{manager.path}`"

    @staticmethod
    def pub(args):
        manager = KeyManager(args.path)

        out = manager.export_public_key()

        return f"Public key exported to `{out}`"

    @staticmethod
    def sign(args):
        manager = KeyManager(args.key)
        private_key = manager.load_key()
        signer = Signer(private_key)

        input_path   = Path(args.path)
        output_path = Path(args.output) if args.output else None

        match args.mode:
            case "detached":
                if not input_path.is_file():
                    raise ValueError(f"Detached mode expects a file, got: {input_path}")
                out = signer.sign_detached(input_path, output_path)
            case "inline":
                if not input_path.is_file():
                    raise ValueError(f"Inline mode expects a file, got: {input_path}")
                out = signer.sign_inline(input_path, output_path)
            case "clearsign":
                if not input_path.is_file():
                    raise ValueError(f"Clearsign mode expects a file, got: {input_path}")
                out = signer.sign_clearsign(input_path, output_path)
            case "manifest":
                if not input_path.is_dir():
                    raise ValueError(f"Manifest mode expects a directory, got: {input_path}")
                pattern = "**/*" if args.recursive else "*"
                files = sorted(f for f in input_path.glob(pattern) if f.is_file())
                if not files:
                    raise ValueError(f"No files found in: {input_path}")
                out = signer.sign_manifest(files, output_path)

        return f"[{args.mode}] Signature written to `{out}`"

    @staticmethod
    def auth(args):
        raise NotImplementedError()

def parse_args():
    parser = argparse.ArgumentParser(description="File Vault")

    sub = parser.add_subparsers(dest="command", required=True)

    # ==== GENKEY ==== #
    p = sub.add_parser("genkey")
    p.add_argument(
        "path",
        nargs="?",
        const=str(KeyManager._DEFAULT_KEY_FILE),
        default=None,  # VALUE IF NOT CALLED
        help="Where to generate the key ( current if empty )",
    )

    p = sub.add_parser("pub")
    p.add_argument(
        "path",
        nargs="?",
        const=str(KeyManager._DEFAULT_KEY_FILE),
        default=None,  # VALUE IF NOT CALLED
        help="Where to generate the key ( current if empty )",
    )

    # ==== sign ==== #
    p = sub.add_parser("sign", help="Sign a file")
    p.add_argument(
        "path",
        help="File to sign (detached/inline) or directory to sign (manifest)",
    )
    p.add_argument(
        "--mode", required=True,
        choices=["detached", "inline", "clearsign", "manifest"],
        help="Signature mode",
    )
    p.add_argument(
        "--key", default=None,
        help=f"Path to the private key (default: {KeyManager._DEFAULT_KEY_FILE})",
    )
    p.add_argument(
        "--output", "-o", default=None,
        help="Custom output path (optional)",
    )

    p.add_argument(
    "--recursive", "-r", action="store_true",
    help="Include files in subdirectories (only for manifest)",
    )

    # ==== verify ==== #
    p = sub.add_parser("auth", help="Verify a signature envelope")
    p.add_argument(
        "envelope",
        help="Path to the .sig or .json envelope",
    )

    # Sets the target function of the command
    for cmd_name, cmd_func in [
        ("genkey", Commands.genkey),
        ("pub", Commands.pub),
        ("sign",  Commands.sign),
        ("auth", Commands.auth),
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
    except (ValueError, FileNotFoundError) as e:
        print(f"\nError: {e}")
        exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        exit(2)


if __name__ == "__main__":
    main()
