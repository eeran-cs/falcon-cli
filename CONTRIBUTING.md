# Contributing

We welcome contributions that improve the CLI. Please ensure that your contributions align with our coding standards and pass all CI checks.

## How to contribute

1. Fork the repository on GitHub
2. Clone your fork and create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes and ensure tests pass (`make test && make lint`)
4. Commit with a descriptive message
5. Push to your fork and open a Pull Request

## Development workflow

See [building.md](building.md) for build targets, testing, and project structure.

## Code style

- Run `make fmt` before committing
- Run `make lint` to catch issues early
- Follow existing patterns in the codebase (cobra commands, factory injection, IO streams)
