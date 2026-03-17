package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCLI_Schema(t *testing.T) {
	bin := buildBinary(t)
	defer os.Remove(bin)
	cmd := exec.Command(bin, "--schema")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sslcheck --schema: %v\nstderr=%s\nstdout=%s", err, stderr.String(), stdout.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &m); err != nil {
		t.Fatalf("schema output not valid JSON: %v (stderr may contain log banner)", err)
	}
	if m["type"] != "object" {
		t.Errorf("schema type = %v", m["type"])
	}
}

func TestCLI_Version(t *testing.T) {
	bin := buildBinary(t)
	defer os.Remove(bin)
	cmd := exec.Command(bin, "--version")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		t.Fatalf("sslcheck --version: %v", err)
	}
	if len(stdout.Bytes()) == 0 {
		t.Error("expected non-empty version output on stdout")
	}
}

func TestCLI_NoURL(t *testing.T) {
	bin := buildBinary(t)
	defer os.Remove(bin)
	cmd := exec.Command(bin)
	_ = cmd.Run()
	if cmd.ProcessState.ExitCode() == 0 {
		t.Error("expected non-zero exit when no URL given")
	}
}

func TestCLI_InvalidProfile(t *testing.T) {
	bin := buildBinary(t)
	defer os.Remove(bin)
	cmd := exec.Command(bin, "--profile=invalid", "https://example.com")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() == 0 {
		t.Errorf("expected non-zero exit for invalid profile\n%s", out)
	}
}

func TestCLI_JSON_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	bin := buildBinary(t)
	defer os.Remove(bin)
	cmd := exec.Command(bin, "--json", "--no-http", "--no-active-ocsp", "https://example.com")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		t.Fatalf("sslcheck --json: %v\n%s", err, stdout.String())
	}
	var rep struct {
		URL     string `json:"url"`
		Host    string `json:"host"`
		Overall string `json:"overall"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("json output not valid: %v", err)
	}
	if rep.Host != "example.com" {
		t.Errorf("host = %q", rep.Host)
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	pkgDir := filepath.Dir(file)
	dir := t.TempDir()
	bin := filepath.Join(dir, "sslcheck")
	if os.Getenv("GOOS") == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = pkgDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}
