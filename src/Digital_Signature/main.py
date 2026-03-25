

import argparse
from keys import KeyManager

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
    def _(args):
        raise NotImplementedError()

    @staticmethod
    def _(args):
        raise NotImplementedError()

    @staticmethod
    def _(args):
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

    # Sets the target function of the command
    for cmd_name, cmd_func in [
        ("genkey", Commands.genkey)
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
