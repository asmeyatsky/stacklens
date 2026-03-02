from __future__ import annotations

import typer

from stacklens.presentation.cli.app import app


@app.command()
def web(
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
) -> None:
    """Launch the StackLens web interface."""
    import uvicorn

    from stacklens.presentation.web.app import webapp

    typer.echo(f"Starting StackLens web UI at http://{host}:{port}")
    uvicorn.run(webapp, host=host, port=port, log_level="info")
