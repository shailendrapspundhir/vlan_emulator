"""Entry point for the Flet desktop application.

Run with:
    python -m home_net_analyzer.desktop
Or via CLI:
    hna desktop
"""

from home_net_analyzer.desktop.app import run_app


def main() -> None:
    """Main entry point for the desktop application."""
    run_app()


if __name__ == "__main__":
    main()
