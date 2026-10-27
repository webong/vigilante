// Package deps extracts application and binary dependency graphs (Go buildinfo,
// go.mod, go.sum, npm package.json, package-lock.json, Rust Cargo.lock, Python
// uv.lock / requirements.txt, and OS shared libraries) and matches them against
// known vulnerability advisories so network flows can be correlated with
// reachable CVEs in the owning process.
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

// Advisory describes a known vulnerability matched against a loaded dependency.
type Advisory struct {
	ID          string `json:"id"`       // e.g. "CVE-2024-24790" or "GHSA-..."
	Package     string `json:"package"`  // Module or package name
	Version     string `json:"version"`  // Loaded version
	FixedIn     string `json:"fixed_in"` // Recommended fixed version
	Severity    string `json:"severity"` // "low", "medium", "high", "critical"
	Description string `json:"description"`
}

// Module represents a single library or runtime dependency.
type Module struct {
	Ecosystem string `json:"ecosystem"` // "go", "npm", "cargo", "pypi", "shared-lib"
	Path      string `json:"path"`
	Version   string `json:"version"`
	Source    string `json:"source"` // "buildinfo", "go.mod", "go.sum", "package.json", "package-lock.json", "Cargo.lock", "uv.lock", "requirements.txt", "mapping"
}

// Graph summarizes the discovered application dependency graph and matched
// vulnerability advisories for a process.
type Graph struct {
	MainModule      string     `json:"main_module,omitempty"`
	GoVersion       string     `json:"go_version,omitempty"`
	ProjectRoot     string     `json:"project_root,omitempty"`
	Dependencies    []Module   `json:"dependencies"`
	Vulnerabilities []Advisory `json:"vulnerabilities,omitempty"`
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

	// 2. Locate nearest project root from workingDir, executable directory, or mapped files.
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
			addModules(seen, &out, parseGoMod(filepath.Join(root, "go.mod")))
			addModules(seen, &out, parseGoSum(filepath.Join(root, "go.sum")))
			addModules(seen, &out, parsePackageLockJSON(filepath.Join(root, "package-lock.json")))
			addModules(seen, &out, parsePackageJSON(filepath.Join(root, "package.json")))
			addModules(seen, &out, parseCargoLock(filepath.Join(root, "Cargo.lock")))
			addModules(seen, &out, parseUVLock(filepath.Join(root, "uv.lock")))
			addModules(seen, &out, parseRequirementsTxt(filepath.Join(root, "requirements.txt")))
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

	out.Vulnerabilities = matchAdvisories(out.Dependencies)
	return out
}

func addModules(seen map[string]Module, out *Graph, mods []Module) {
	for _, m := range mods {
		if out.MainModule == "" && strings.HasSuffix(m.Source, ":module") {
			out.MainModule = m.Path
			continue
		}
		key := m.Ecosystem + ":" + m.Path
		if _, exists := seen[key]; !exists {
			seen[key] = m
		}
	}
}

func findProjectRoot(start string) string {
	dir, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		for _, marker := range []string{
			"go.mod", "package-lock.json", "package.json",
			"Cargo.lock", "uv.lock", "requirements.txt", ".ctx", ".git",
		} {
			if st, err := os.Stat(filepath.Join(dir, marker)); err == nil && !st.IsDir() {
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

func parseGoSum(path string) []Module {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var modules []Module
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		modPath := fields[0]
		ver := strings.TrimSuffix(fields[1], "/go.mod")
		key := modPath + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		modules = append(modules, Module{
			Ecosystem: "go",
			Path:      modPath,
			Version:   ver,
			Source:    "go.sum",
		})
	}
	return modules
}

func parsePackageJSON(path string) []Module {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pkg struct {
		Name            string            `json:"name"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	var modules []Module
	if pkg.Name != "" {
		modules = append(modules, Module{
			Ecosystem: "npm",
			Path:      pkg.Name,
			Source:    "package.json:module",
		})
	}
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

func parsePackageLockJSON(path string) []Module {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock struct {
		Name     string `json:"name"`
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var modules []Module
	if lock.Name != "" {
		modules = append(modules, Module{
			Ecosystem: "npm",
			Path:      lock.Name,
			Source:    "package-lock.json:module",
		})
	}
	for pkgPath, info := range lock.Packages {
		if pkgPath == "" || info.Version == "" {
			continue
		}
		name := pkgPath
		if idx := strings.LastIndex(pkgPath, "node_modules/"); idx >= 0 {
			name = pkgPath[idx+len("node_modules/"):]
		}
		modules = append(modules, Module{
			Ecosystem: "npm",
			Path:      name,
			Version:   info.Version,
			Source:    "package-lock.json",
		})
	}
	for name, info := range lock.Dependencies {
		if name == "" || info.Version == "" {
			continue
		}
		modules = append(modules, Module{
			Ecosystem: "npm",
			Path:      name,
			Version:   info.Version,
			Source:    "package-lock.json",
		})
	}
	return modules
}

func parseCargoLock(path string) []Module {
	return parseTOMLPackages(path, "cargo", "Cargo.lock")
}

func parseUVLock(path string) []Module {
	return parseTOMLPackages(path, "pypi", "uv.lock")
}

func parseTOMLPackages(path, ecosystem, source string) []Module {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var modules []Module
	var curName, curVer string
	flush := func() {
		if curName != "" && curVer != "" {
			modules = append(modules, Module{
				Ecosystem: ecosystem,
				Path:      curName,
				Version:   curVer,
				Source:    source,
			})
		}
		curName, curVer = "", ""
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "name =") {
			curName = trimTOMLString(strings.TrimPrefix(line, "name ="))
		} else if strings.HasPrefix(line, "version =") {
			curVer = trimTOMLString(strings.TrimPrefix(line, "version ="))
		}
	}
	flush()
	return modules
}

func trimTOMLString(s string) string {
	s = strings.TrimSpace(s)
	return strings.Trim(s, `"'`)
}

func parseRequirementsTxt(path string) []Module {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var modules []Module
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		for _, sep := range []string{"==", ">=", "~=", "<="} {
			if name, ver, ok := strings.Cut(line, sep); ok {
				modules = append(modules, Module{
					Ecosystem: "pypi",
					Path:      strings.TrimSpace(name),
					Version:   strings.TrimSpace(ver),
					Source:    "requirements.txt",
				})
				break
			}
		}
	}
	return modules
}

type rule struct {
	ecosystem   string
	pkg         string
	badPrefixes []string
	advisory    Advisory
}

var builtinAdvisoryRules = []rule{
	{
		ecosystem:   "go",
		pkg:         "golang.org/x/net",
		badPrefixes: []string{"v0.0.", "v0.1.", "v0.2.", "v0.3.", "v0.4.", "v0.5.", "v0.6.", "v0.7.", "v0.8.", "v0.9.", "v0.10.", "v0.11.", "v0.12.", "v0.13.", "v0.14.", "v0.15.", "v0.16.", "v0.17.", "v0.18.", "v0.19.", "v0.20.", "v0.21.", "v0.22."},
		advisory: Advisory{
			ID:          "CVE-2023-45288",
			Package:     "golang.org/x/net",
			FixedIn:     "v0.23.0",
			Severity:    "high",
			Description: "HTTP/2 CONTINUATION frame flood DoS in golang.org/x/net",
		},
	},
	{
		ecosystem:   "npm",
		pkg:         "express",
		badPrefixes: []string{"4.17.", "4.18.", "4.19.0", "4.19.1"},
		advisory: Advisory{
			ID:          "CVE-2024-29041",
			Package:     "express",
			FixedIn:     "4.19.2",
			Severity:    "medium",
			Description: "Open redirect vulnerability in Express response.location()",
		},
	},
	{
		ecosystem:   "npm",
		pkg:         "lodash",
		badPrefixes: []string{"4.17.15", "4.17.19", "4.17.20"},
		advisory: Advisory{
			ID:          "CVE-2021-23337",
			Package:     "lodash",
			FixedIn:     "4.17.21",
			Severity:    "high",
			Description: "Command injection via template function in lodash",
		},
	},
	{
		ecosystem:   "pypi",
		pkg:         "urllib3",
		badPrefixes: []string{"1.26.", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.0.6"},
		advisory: Advisory{
			ID:          "CVE-2023-45803",
			Package:     "urllib3",
			FixedIn:     "2.0.7",
			Severity:    "medium",
			Description: "Request body not stripped on HTTP redirect in urllib3",
		},
	},
}

func matchAdvisories(mods []Module) []Advisory {
	var out []Advisory
	for _, m := range mods {
		cleanVer := strings.TrimLeft(m.Version, "^~=")
		for _, r := range builtinAdvisoryRules {
			if m.Ecosystem != r.ecosystem || m.Path != r.pkg {
				continue
			}
			for _, prefix := range r.badPrefixes {
				if strings.HasPrefix(cleanVer, prefix) || strings.HasPrefix(m.Version, prefix) {
					adv := r.advisory
					adv.Version = m.Version
					out = append(out, adv)
					break
				}
			}
		}
	}
	return out
}
