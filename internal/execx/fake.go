package execx

import (
	"context"
	"fmt"
)

// FakeCall records a single invocation of FakeRunner.Run.
type FakeCall struct {
	Name  string
	Args  []string
	Stdin []byte
}

// FakeResult defines the canned response for a FakeRunner invocation.
type FakeResult struct {
	Stdout []byte
	Stderr []byte
	Err    error
}

// FakeRunner is a test double that returns canned results in order.
// After all results are consumed, further calls return an error.
type FakeRunner struct {
	results []FakeResult
	Calls   []FakeCall
	next    int
}

// NewFakeRunner creates a FakeRunner with the given canned results.
func NewFakeRunner(results ...FakeResult) *FakeRunner {
	return &FakeRunner{results: results}
}

func (f *FakeRunner) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, []byte, error) {
	f.Calls = append(f.Calls, FakeCall{Name: name, Args: args, Stdin: stdin})
	if f.next >= len(f.results) {
		return nil, nil, fmt.Errorf("FakeRunner: no more results (call %d)", f.next+1)
	}
	r := f.results[f.next]
	f.next++
	return r.Stdout, r.Stderr, r.Err
}
