package pathguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxScanFileBytes caps how much we read from any single file.
	MaxScanFileBytes = 512 * 1024
)

// ResolveRoot turns a user-supplied path into an absolute, cleaned root.
// This is hardening 101: never scan relative to cwd blindly.
func ResolveRoot(root string) (string, error) {
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	clean := filepath.Clean(abs)
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("stat root %q: %w", clean, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("root %q is not a directory", clean)
	}
	return clean, nil
}

// SafeJoin joins root + relative path and rejects traversal escapes.
// Python's Path.resolve() is similar; Go makes the check explicit.
func SafeJoin(root, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute paths not allowed: %q", rel)
	}
	joined := filepath.Join(root, rel)
	clean := filepath.Clean(joined)
	rootClean := filepath.Clean(root)
	if clean != rootClean && !strings.HasPrefix(clean, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes scan root: %q", rel)
	}
	return clean, nil
}

// ReadBounded reads up to MaxScanFileBytes from a file inside root.
func ReadBounded(root, rel string) ([]byte, error) {
	full, err := SafeJoin(root, rel)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxScanFileBytes {
		return nil, fmt.Errorf("file too large (%d bytes): %q", info.Size(), rel)
	}
	return os.ReadFile(full)
}