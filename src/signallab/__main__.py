"""Allow ``python -m signallab`` without relying on installed entry points."""

from .cli import main

raise SystemExit(main())
