# Contributing to angie-modsecurity-docker

Thank you for your interest in contributing!

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Docker version)

### Suggesting Features

Open an issue with:
- Use case description
- Proposed solution
- Alternatives considered

### Pull Requests

1. Fork the repository
2. Create a feature branch from `dev`:
   ```bash
   git checkout dev
   git checkout -b feature/your-feature
   ```
3. Make your changes
4. Test locally:
   ```bash
   make dev
   make test
   ```
5. Commit with clear messages
6. Push and create PR to `dev` branch

### Code Style

- Follow existing code patterns
- Add comments for complex logic
- Update documentation if needed

### Testing

Before submitting PR:
- Run `make lint`
- Run `make test`
- Verify container starts healthy

## Development Setup

```bash
git clone https://github.com/hvaclab/angie-modsecurity-docker.git
cd angie-modsecurity-docker
make dev
```

## Questions?

Open an issue with the "question" label.
