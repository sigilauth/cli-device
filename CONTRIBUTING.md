# Contributing to Sigil CLI Device

Thank you for your interest in contributing to the Sigil Auth CLI testing device!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/cli-device.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `go test -race -timeout 60s ./...`
6. Check coverage: `go test -cover ./...` (target: 85%+)
7. Commit with conventional commits: `git commit -m "feat: add new subcommand"`
8. Push to your fork: `git push origin feature/your-feature-name`
9. Open a Pull Request

## Code Quality Standards

- **Test-Driven Development:** Write tests BEFORE implementation
- **Coverage:** Minimum 85% coverage per package
- **Race-free:** All tests must pass with `-race` flag
- **Idiomatic Go:** Follow Go proverbs and effective Go guidelines
- **Error handling:** All errors must be handled or explicitly ignored with comment
- **No shortcuts:** Production quality only, no TODOs or stubs

## Commit Message Format

Use conventional commits:

- `feat:` - New feature
- `fix:` - Bug fix
- `test:` - Add or update tests
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Build process or auxiliary tool changes

## Testing

Run the full test suite:

```bash
# Unit tests with race detector
go test -race -timeout 60s ./...

# Coverage report
go test -cover ./...

# Coverage HTML report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if adding/changing features
3. Add tests for new functionality
4. Keep PRs focused on a single feature/fix
5. Respond to review feedback promptly

## Code Review Checklist

Before submitting your PR, verify:

- [ ] Tests pass with `-race` flag
- [ ] Coverage is 85%+ for changed code
- [ ] No `panic()` in production code
- [ ] All errors are handled
- [ ] No goroutines without cancellation mechanism
- [ ] Code follows Go style guide
- [ ] Documentation updated (if applicable)
- [ ] No hardcoded values (use constants or config)

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
