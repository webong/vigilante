// Package deps extracts application and binary dependency graphs (Go buildinfo,
// go.mod, and npm package.json) so network flows can be correlated with the
// exact libraries loaded by the owning process.
package deps

import (
	"bufio"
	"debug/buildinfo"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Module represents a single library or runtime dependency.
type Module struct {
	Ecosystem string `json:"ecosystem"` // "go", "npm", "shared-lib"
	Path      string `json:"path"`
	Version   string `json:"version"`
	Source    string `json:"source"` // "buildinfo", "go.mod", "package.json", "mapping"
}

// Graph summarizes the discovered application dependency graph for a process.
type Graph struct {
	MainModule   string   `json:"main_module,omitempty"`
	GoVersion    string   `json:"go_version,omitempty"`
	ProjectRoot  string   `json:"project_root,omitempty"`
	Dependencies []Module `json:"dependencies"`
}

// Inspect discovers dependencies from a compiled binary path, an optional
// working directory, and any OS memory-mapped library paths reported by
// res/system.InspectProcess.
func Inspect(executablePath, workingDir string, mappedFiles []string) Graph {
	seen := make(map[string]Module)
	var out Graph

	// 1. Inspect compiled Go binary buildinfo if executable exists.
	if executablePath != "" {
		if info, err := buildinfo.ReadFile(executablePath); err == nil {
			out.GoVersion = info.GoVersion
			if info.Main.Path != "" {
				out.MainModule = info.Main.Path
			}
			for _, dep := range info.Deps {
				if dep == nil || dep.Path == "" {
					continue
				}
				version := dep.Version
				if dep.Replace != nil && dep.Replace.Version != "" {
					version = dep.Replace.Version
				}
				key := "go:" + dep.Path
				seen[key] = Module{
					Ecosystem: "go",
					Path:      dep.Path,
					Version:   version,
					Source:    "buildinfo",
				}
			}
		}
	}

	// 2. Locate nearest project root from workingDir or executable directory.
	searchDirs := []string{}
	if workingDir != "" {
		searchDirs = append(searchDirs, workingDir)
	}
	if executablePath != "" {
		searchDirs = append(searchDirs, filepath.Dir(executablePath))
	}
	for _, start := range searchDirs {
		if root := findProjectRoot(start); root != "" {
			if out.ProjectRoot == "" {
				out.ProjectRoot = root
			}
			for _, m := range parseGoMod(filepath.Join(root, "go.mod")) {
				if out.MainModule == "" && m.Source == "go.mod:module" {
					out.MainModule = m.Path
					continue
				}
				key := "go:" + m.Path
				if _, exists := seen[key]; !exists {
					seen[key] = m
				}
			}
			for _, m := range parsePackageJSON(filepath.Join(root, "package.json")) {
				key := "npm:" + m.Path
				if _, exists := seen[key]; !exists {
					seen[key] = m
				}
			}
		}
	}

	// 3. Include dynamic library mappings observed by ext/res/system.
	for _, path := range mappedFiles {
		path = strings.TrimSpace(path)
		if path == "" || path == executablePath {
			continue
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".dylib" || ext == ".so" || ext == ".dll" || strings.Contains(path, ".so.") {
			base := filepath.Base(path)
			key := "shared-lib:" + path
			seen[key] = Module{
				Ecosystem: "shared-lib",
				Path:      path,
				Version:   base,
				Source:    "mapping",
			}
		}
	}

	out.Dependencies = make([]Module, 0, len(seen))
	for _, m := range seen {
		out.Dependencies = append(out.Dependencies, m)
	}
	sort.Slice(out.Dependencies, func(i, j int) bool {
		a, b := out.Dependencies[i], out.Dependencies[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		return a.Path < b.Path
	})
	return out
}

func findProjectRoot(start string) string {
	dir, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		for _, marker := range []string{"go.mod", "package.json", ".ctx", ".git"} {
			if info, err := os.Stat(filepath.Join(dir, marker)); err == nil && !info.IsDir() {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func parseGoMod(path string) []Module {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var modules []Module
	inRequire := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "module ") {
			modName := strings.TrimSpace(strings.TrimPrefix(line, "module "))
			if modName != "" {
				modules = append(modules, Module{
					Ecosystem: "go",
					Path:      modName,
					Source:    "go.mod:module",
				})
			}
			continue
		}
		if strings.HasPrefix(line, "require (") || line == "require(" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "require "))
			fields := strings.Fields(rest)
			if len(fields) >= 2 {
				modules = append(modules, Module{
					Ecosystem: "go",
					Path:      fields[0],
					Version:   fields[1],
					Source:    "go.mod",
				})
			}
			continue
		}
		if inRequire {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				modules = append(modules, Module{
					Ecosystem: "go",
					Path:      fields[0],
					Version:   fields[1],
					Source:    "go.mod",
				})
			}
		}
	}
	return modules
}

func parsePackageJSON(path string) []Module {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	var modules []Module
	for name, ver := range pkg.Dependencies {
		modules = append(modules, Module{
			Ecosystem: "npm",
			Path:      name,
			Version:   ver,
			Source:    "package.json",
		})
	}
	for name, ver := range pkg.DevDependencies {
		modules = append(modules, Module{
			Ecosystem: "npm",
			Path:      name,
			Version:   ver,
			Source:    "package.json",
		})
	}
	return modules
}
