package executor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Fake is a test executor: file ops act on hostfs.Root like Local (no allowlist bypass),
// commands are recorded and answered from Outputs ("cmd arg1 arg2" -> output), never executed.
type Fake struct {
	mu      sync.Mutex
	Calls   []string
	Outputs map[string]string
	Errors  map[string]error
	Local
}

func NewFake() *Fake { return &Fake{Outputs: map[string]string{}, Errors: map[string]error{}} }

func (f *Fake) Run(_ context.Context, cmd string, args ...string) ([]byte, error) {
	if err := Allowed(cmd, args); err != nil {
		return nil, err
	}
	k := strings.TrimSpace(cmd + " " + strings.Join(args, " "))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, k)
	if err, ok := f.Errors[k]; ok {
		return []byte(f.Outputs[k]), err
	}
	if out, ok := f.Outputs[k]; ok {
		return []byte(out), nil
	}
	// prefix match lets tests answer a family of calls
	for p, out := range f.Outputs {
		if strings.HasSuffix(p, "*") && strings.HasPrefix(k, strings.TrimSuffix(p, "*")) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

// Chown is a no-op in tests (temp files belong to the test user).
func (f *Fake) Chown(p string, uid, gid int) error {
	if !writable(p) && !writable(p+"/") {
		return ErrDenied
	}
	return nil
}

// Called reports whether a call with the given prefix was made.
func (f *Fake) Called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.Calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *Fake) String() string { return fmt.Sprint(f.Calls) }

var _ Executor = (*Fake)(nil)
var _ = os.ModePerm
