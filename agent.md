# Agent entry point

The authoritative project instructions are in [`AGENTS.md`](AGENTS.md).

This is a dependency-light educational web app for tracing iterative DNS resolution. The Python server and embedded frontend are in `main.py`. Start it with `.venv/bin/python main.py`, open `http://127.0.0.1:8000`, and validate with `python -m py_compile main.py`.

Keep DNS queries non-recursive and maintain the flat, square-cornered interface described in `AGENTS.md`.
