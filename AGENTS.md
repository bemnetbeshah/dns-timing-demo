# DNS Timing Demo

This project is a small educational web app that demonstrates iterative DNS resolution.

## Structure and conventions

- Keep the app dependency-light; the server and frontend live in `main.py`.
- Use non-recursive DNS queries so each resolver hop remains visible.
- Preserve the flat visual language: solid colors, square corners, and no glow effects.
- Validate changes with `python -m py_compile main.py` and run with `.venv/bin/python main.py`.

## Folder indexes

- [`index.md`](index.md) — project root contents.
