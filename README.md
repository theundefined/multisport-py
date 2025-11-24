# multisport-py

A Python library for interacting with the MultiSport API.

## Installation

```bash
pip install multisport-py
```

## Usage

For a complete, working example of how to use the library, please see the `simple_usage.py` file in the `examples` directory.

[» View Example: `examples/simple_usage.py`](./examples/simple_usage.py)

To run the example, you will need to:
1. Create a `.env` file in the root of the project (you can copy `.env.example`).
2. Fill in your `MULTISPORT_USERNAME` and `MULTISPORT_PASSWORD`.
3. Run the script:
   ```bash
   python examples/simple_usage.py
   ```

## Development

To set up the development environment:

1. Clone the repository:
   ```bash
   git clone https://github.com/TheUndefined/multisport-py.git
   cd multisport-py
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
3. Install development dependencies:
   ```bash
   pip install hatchling pytest ruff black mypy httpx
   pip install -e . # Install the library in editable mode
   ```

## Running Tests

```bash
pytest
```

## Formatting and Linting

```bash
black .
ruff check . --fix
mypy src
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
