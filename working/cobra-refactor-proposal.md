# Cobra Framework Refactor — v0.2.0 Proposal

## Summary

Refactor `sigil-device` CLI from custom switch/case implementation to `github.com/spf13/cobra` framework for better maintainability and automatic completion generation.

## Current State (v0.1.0)

- **Implementation:** Custom CLI with manual switch/case in `cmd/sigil-device/main.go`
- **Completions:** Manually written bash/zsh/fish scripts (~150 lines total)
- **Help text:** Hardcoded in `fmt.Fprintf` calls
- **Flags:** Manual parsing in each command function

## Proposed State (v0.2.0)

- **Implementation:** Cobra with root command + 9 subcommands
- **Completions:** Auto-generated via `cobra` built-in (`sigil-device completion bash|zsh|fish`)
- **Help text:** Declarative via `cobra.Command` structs
- **Flags:** Declarative via `pflag` integration

## Benefits

1. **Zero-maintenance completions** — No manual updates when commands/flags change
2. **Consistent UX** — Industry-standard help formatting, error messages, flag parsing
3. **Better discoverability** — Built-in `help` command, `--help` on every subcommand
4. **Easier extension** — Adding new commands = new `cobra.Command` struct, not switch case
5. **Persistent flags** — Global flags (like `--verbose`, `--config`) propagate to all subcommands
6. **Testing infrastructure** — Cobra commands are testable in isolation

## Drawbacks

1. **Binary size** — Adds ~200KB to binary (Cobra + pflag dependencies)
2. **Import overhead** — Two new dependencies (`github.com/spf13/cobra`, `github.com/spf13/pflag`)
3. **Migration effort** — Estimate 2-3 hours to refactor all 9 commands

## Implementation Scope

### 1. Root command setup (`cmd/sigil-device/main.go`)

```go
var rootCmd = &cobra.Command{
    Use:   "sigil-device",
    Short: "CLI-based testing device for Sigil Auth",
    Version: version,
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

### 2. Subcommands (`cmd/sigil-device/cmd_*.go`)

Each command function becomes a `cobra.Command`:

```go
var pairCmd = &cobra.Command{
    Use:   "pair",
    Short: "Pair with Sigil server",
    RunE: func(cmd *cobra.Command, args []string) error {
        server, _ := cmd.Flags().GetString("server")
        return cmdPair(server)
    },
}

func init() {
    pairCmd.Flags().StringP("server", "s", "", "Sigil server URL (required)")
    pairCmd.MarkFlagRequired("server")
    rootCmd.AddCommand(pairCmd)
}
```

### 3. Completion generation (remove manual scripts)

Users run `sigil-device completion bash > /etc/bash_completion.d/sigil-device` (or equivalent). GoReleaser `post-build` hook generates completion files for packaging.

### 4. Update GoReleaser hooks

```yaml
before:
  hooks:
    - go mod tidy
    - go test -race -timeout 60s ./...
    - mkdir -p completions
    - ./sigil-device completion bash > completions/sigil-device.bash
    - ./sigil-device completion zsh > completions/sigil-device.zsh
    - ./sigil-device completion fish > completions/sigil-device.fish
```

## Testing Strategy

- Unit test each command's flag parsing and validation
- Integration test: verify `--help` output for all commands
- Regression test: ensure all existing command behaviors preserved

## Rollout Plan

1. **v0.1.0 ships** with manual completions (current state)
2. **v0.2.0 development:**
   - @kai refactors to Cobra in feature branch
   - Replace manual completion scripts with Cobra-generated ones
   - Update GoReleaser hooks
   - Full regression test suite
3. **v0.2.0 release:**
   - Tag + publish with auto-generated completions
   - Update README to document `completion` subcommand

## Decision

**Defer to v0.2.0.** Manual completions ship in v0.1.0 (acceptable for initial release). Cobra refactor happens post-ship when no release pressure.

## References

- [Cobra documentation](https://github.com/spf13/cobra)
- [Cobra User Guide](https://github.com/spf13/cobra/blob/main/user_guide.md)
- [Completion generation](https://github.com/spf13/cobra/blob/main/shell_completions.md)
