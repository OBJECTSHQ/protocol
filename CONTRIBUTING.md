# Contributing to OBJECTS Protocol

Thank you for your interest in contributing to OBJECTS Protocol! This document provides guidelines and information to help you contribute effectively.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@objects.foundation.

## Ways to Contribute

- **Report bugs** - File detailed bug reports using our [issue templates](.github/ISSUE_TEMPLATE/)
- **Suggest features** - Propose new features or improvements via GitHub issues
- **Submit fixes** - Open pull requests for bug fixes
- **Improve documentation** - Help improve docs, examples, and guides
- **Review PRs** - Provide feedback on open pull requests

## Reporting Issues

Before creating an issue, please search existing issues to avoid duplicates. When reporting:

- Use the appropriate [issue template](.github/ISSUE_TEMPLATE/)
- Provide clear reproduction steps for bugs
- Include relevant environment details (OS, Rust version, etc.)

## Development Setup

1. **Prerequisites**
   - Rust (latest stable) - install via [rustup](https://rustup.rs/)
   - Protocol Buffers compiler (`protoc`)
   - Docker - install via [Docker Desktop](https://www.docker.com/products/docker-desktop/) or your package manager

2. **Clone and build**
   ```bash
   git clone https://github.com/OBJECTSHQ/protocol.git
   cd protocol
   cp .env.example .env
   cargo build --workspace
   ```

3. **Run tests**
   ```bash
   cargo test --workspace
   ```

4. **E2E tests** (require Docker)
   ```bash
   docker compose -f docker/test-compose.yml up -d
   cargo test -p objects-node --test e2e_full_stack
   docker compose -f docker/test-compose.yml down
   ```

   > **Note:** Unit and integration tests run without Docker. Only `objects-node` E2E tests require the Docker-based test registry.

## CLI Reference

The `objects-cli` tool communicates with a running node via its HTTP API.

```bash
cargo run -p objects-cli -- <command>
```

| Command | Description |
|---------|-------------|
| `init` | Initialize a new node |
| `status` | Show node status |
| `identity create --handle <name>` | Create a new identity |
| `identity show` | Show current identity |
| `project create --name <name> [-d <desc>]` | Create a project |
| `project list` | List all projects |
| `project get <id>` | Get project by ID (32 hex chars) |
| `asset add --project <id> <file>` | Add a file as an asset |
| `asset list --project <id>` | List assets in a project |
| `ticket create --project <id>` | Generate a share ticket |
| `ticket redeem <ticket>` | Join a project via ticket |
| `sync` | Sync with peers |

## Making Changes

1. **Fork the repository** and create your branch from `main`

2. **Make your changes**
   - Keep changes focused and atomic
   - Follow existing code patterns and style
   - Add tests for new functionality

3. **Test your changes**
   ```bash
   cargo fmt --all              # Format code
   cargo clippy --workspace -- -D warnings  # Lint
   cargo test --workspace       # Run tests
   ```

4. **Commit with a clear message** following [conventional commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `refactor:` code refactoring
   - `test:` adding or updating tests
   - `docs:` documentation changes
   - `chore:` build, CI, or tooling
   - `perf:` performance improvement
   - `ci:` CI/CD configuration

5. **Open a pull request** using our [PR template](.github/PULL_REQUEST_TEMPLATE.md)

## Pull Request Process

1. Fill out the PR template completely
2. Ensure all CI checks pass
3. Request review from maintainers
4. Address review feedback
5. Maintainers will merge once approved

### Stacked PRs

For large changes, consider breaking them into stacked PRs:
- Add the `stack` label to all PRs in the stack
- Use `Depends on: #123` to indicate dependencies
- Each PR should be independently reviewable

## Code Style

- **Format**: Run `cargo fmt --all` before committing
- **Lint**: Ensure `cargo clippy --workspace -- -D warnings` passes
- **Test**: All tests must pass with `cargo test --workspace`

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project:

- [Apache License 2.0](LICENSE-APACHE)
- [MIT License](LICENSE)

at the contributor's option.

## Questions?

If you have questions, feel free to open a discussion or reach out to the maintainers.
