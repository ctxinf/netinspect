// Package preload embeds the LD_PRELOAD interception library and extracts
// it at runtime. Build the .so first: make -C modes/preload
package preload

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed libnetinspect.so
var soBytes []byte

// Extract writes the embedded .so into dir and returns its path.
func Extract(dir string) (string, error) {
	if len(soBytes) == 0 {
		return "", fmt.Errorf("libnetinspect.so not embedded; run: make -C modes/preload")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "libnetinspect.so")
	if err := os.WriteFile(p, soBytes, 0755); err != nil {
		return "", err
	}
	return p, nil
}
