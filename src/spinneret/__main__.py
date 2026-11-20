"""Allow `python -m spinneret`."""

from spinneret.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
