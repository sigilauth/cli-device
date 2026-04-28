# Go Code Violations Log — cli-device

Append-only log of code quality violations found during review. Each entry includes date, file, line, violation number (from quality bar table), description, and status.

Format: `| date | file | line | violation # | description | status |`

---

## 2026-04-26 — Domain Separation V1 Implementation

**Review scope:** `internal/crypto/ecdsa.go`, `internal/crypto/domain_test.go`, `cmd/sigil-device/cmd_respond.go`, `cmd/sigil-device/cmd_respond_test.go`

**Result:** No violations found.

**Notes:**
- All error returns wrapped with context using `%w`
- No `interface{}` or `any` usage (used `map[string]interface{}` only for JSON unmarshaling)
- All tests table-driven with subtests
- All mutexes properly deferred (none in this implementation)
- All channels properly owned (none in this implementation)
- No global mutable state
- `go fmt` applied to all files
- `go test -race` passes clean
- All exported functions have godoc comments

**Coverage:** 87.3% on crypto package, 80.6% overall (above 80% gate)
