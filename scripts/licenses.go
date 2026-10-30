// Run from the caddy module: go run ../scripts/licenses.go /out/licenses
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("output directory required")
	}
	out := os.Args[1]
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	data, e := cmd.Output()
	if e != nil {
		return e
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var m struct{ Path, Version, Dir string }
		e = d.Decode(&m)
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if m.Dir == "" {
			continue
		}
		entries, e := os.ReadDir(m.Dir)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			n := strings.ToUpper(entry.Name())
			if entry.IsDir() || !(strings.HasPrefix(n, "LICENSE") || strings.HasPrefix(n, "NOTICE") || strings.HasPrefix(n, "COPYING")) {
				continue
			}
			b, e := os.ReadFile(filepath.Join(m.Dir, entry.Name()))
			if e != nil {
				return e
			}
			dir := filepath.Join(out, strings.ReplaceAll(m.Path, "/", "_")+"@"+m.Version)
			if e = os.MkdirAll(dir, 0755); e != nil {
				return e
			}
			if e = os.WriteFile(filepath.Join(dir, entry.Name()), b, 0644); e != nil {
				return e
			}
		}
	}
	return nil
}
