import typer

app = typer.Typer(
    name="stacklens",
    help="AI-augmented web analysis platform",
    no_args_is_help=True,
)


def _register_commands() -> None:
    """Import command modules so they register on ``app``."""
    import stacklens.presentation.cli.commands.analyze  # noqa: F401
    import stacklens.presentation.cli.commands.report  # noqa: F401


_register_commands()
