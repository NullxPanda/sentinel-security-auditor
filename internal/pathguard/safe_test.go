package pathguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeJoinRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	_, err := SafeJoin(root, "../../../etc/passwd")
	if err == nil {
		t.Fatal("expected traversal to be rejected")
	}
}

func TestReadBoundedRespectsRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "ok.txt")
	if err := os.WriteFile(inside, []byte("hello sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := ReadBounded(root, "ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello sentinel" {
		t.Fatalf("got %q", data)
	}
}