package execx

import (
	"context"
	"fmt"
	"runtime"
	"testing"
)

func TestRealRunner_Echo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("echo test assumes unix shell")
	}
	r := RealRunner{}
	stdout, stderr, err := r.Run(context.Background(), "echo", []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("Run() error = %v, stderr = %q", err, stderr)
	}
	if got := string(stdout); got != "hello\n" {
		t.Errorf("stdout = %q, want %q", got, "hello\n")
	}
}

func TestRealRunner_Stdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cat test assumes unix shell")
	}
	r := RealRunner{}
	stdout, _, err := r.Run(context.Background(), "cat", nil, []byte("from stdin"))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := string(stdout); got != "from stdin" {
		t.Errorf("stdout = %q, want %q", got, "from stdin")
	}
}

func TestRealRunner_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := RealRunner{}
	_, _, err := r.Run(ctx, "sleep", []string{"10"}, nil)
	if err == nil {
		t.Fatal("Run() should fail with cancelled context")
	}
}

func TestFakeRunner_ReturnsCannedResults(t *testing.T) {
	fake := NewFakeRunner(
		FakeResult{Stdout: []byte("out1"), Stderr: []byte("err1")},
		FakeResult{Stdout: []byte("out2"), Err: fmt.Errorf("boom")},
	)

	stdout, stderr, err := fake.Run(context.Background(), "cmd1", []string{"a"}, nil)
	if err != nil {
		t.Fatalf("call 1: unexpected error %v", err)
	}
	if string(stdout) != "out1" || string(stderr) != "err1" {
		t.Errorf("call 1: stdout=%q stderr=%q", stdout, stderr)
	}

	stdout, _, err = fake.Run(context.Background(), "cmd2", []string{"b"}, []byte("in"))
	if err == nil || err.Error() != "boom" {
		t.Errorf("call 2: err = %v, want boom", err)
	}
	if string(stdout) != "out2" {
		t.Errorf("call 2: stdout = %q, want %q", stdout, "out2")
	}
}

func TestFakeRunner_RecordsCalls(t *testing.T) {
	fake := NewFakeRunner(FakeResult{}, FakeResult{})

	fake.Run(context.Background(), "kubectl", []string{"get", "pods"}, nil)
	fake.Run(context.Background(), "helm", []string{"install"}, []byte("values"))

	if len(fake.Calls) != 2 {
		t.Fatalf("len(Calls) = %d, want 2", len(fake.Calls))
	}

	c0 := fake.Calls[0]
	if c0.Name != "kubectl" || len(c0.Args) != 2 || c0.Args[0] != "get" {
		t.Errorf("call 0 = %+v", c0)
	}
	if c0.Stdin != nil {
		t.Errorf("call 0 stdin = %v, want nil", c0.Stdin)
	}

	c1 := fake.Calls[1]
	if c1.Name != "helm" || string(c1.Stdin) != "values" {
		t.Errorf("call 1 = %+v", c1)
	}
}

func TestFakeRunner_ExhaustedResults(t *testing.T) {
	fake := NewFakeRunner(FakeResult{Stdout: []byte("only")})

	fake.Run(context.Background(), "a", nil, nil)
	_, _, err := fake.Run(context.Background(), "b", nil, nil)
	if err == nil {
		t.Fatal("expected error when results exhausted")
	}
}
