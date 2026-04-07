package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const defaultRepo = "https://github.com/trufflesecurity/trufflehog.git"

type testFixture struct {
	Detector string
	Name     string
	Input    string
	Wants    []string
}

func main() {
	repo := flag.String("repo", defaultRepo, "TruffleHog git repository to clone")
	out := flag.String("out", "tests/generated_trufflehog_pattern_fixtures.rs", "Output Rust fixture file")
	flag.Parse()

	tmpDir, err := os.MkdirTemp("", "trufflehog-pattern-fixtures-")
	must(err)
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "trufflehog")
	run("git", "clone", "--depth", "1", *repo, repoDir)
	commit := strings.TrimSpace(output("git", "-C", repoDir, "rev-parse", "HEAD"))

	fixtures, err := collectFixtures(repoDir)
	must(err)
	writeFixtures(*out, *repo, commit, fixtures)
	fmt.Printf("wrote %s with %d positive pattern fixtures\n", *out, len(fixtures))
}

func collectFixtures(repoDir string) ([]testFixture, error) {
	root := filepath.Join(repoDir, "pkg", "detectors")
	var files []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") || strings.HasSuffix(d.Name(), "_integration_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(files)

	var fixtures []testFixture
	var extractErrs []string
	for _, path := range files {
		fileFixtures, err := extractFixturesFromFile(root, path)
		if err != nil {
			extractErrs = append(extractErrs, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		fixtures = append(fixtures, fileFixtures...)
	}

	if len(extractErrs) > 0 {
		return nil, errors.New(strings.Join(extractErrs, "\n"))
	}
	return fixtures, nil
}

func extractFixturesFromFile(root, path string) ([]testFixture, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	env, err := collectStringBindings(file)
	if err != nil {
		return nil, err
	}

	detectorDir, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	detectorDir = filepath.ToSlash(detectorDir)

	var fixtures []testFixture
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || !strings.HasSuffix(fn.Name.Name, "_Pattern") || fn.Body == nil {
			continue
		}

		testsLit, err := findTestsCompositeLit(fn.Body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fn.Name.Name, err)
		}
		if testsLit == nil {
			continue
		}

		extracted, err := extractFixturesFromComposite(detectorDir, testsLit, env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fn.Name.Name, err)
		}
		fixtures = append(fixtures, extracted...)
	}

	return fixtures, nil
}

func findTestsCompositeLit(body *ast.BlockStmt) (*ast.CompositeLit, error) {
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		name, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || name.Name != "tests" {
			continue
		}
		lit, ok := assign.Rhs[0].(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("tests assignment was not a composite literal")
		}
		return lit, nil
	}
	return nil, nil
}

func collectStringBindings(file *ast.File) (map[string]string, error) {
	env := make(map[string]string)
	progress := true

	for progress {
		progress = false
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.VAR && gen.Tok != token.CONST) {
				continue
			}
			for _, spec := range gen.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range valueSpec.Names {
					if _, exists := env[name.Name]; exists {
						continue
					}
					if len(valueSpec.Values) == 0 {
						continue
					}
					exprIndex := min(i, len(valueSpec.Values)-1)
					value, ok := evalString(valueSpec.Values[exprIndex], env)
					if !ok {
						continue
					}
					env[name.Name] = value
					progress = true
				}
			}
		}
	}

	return env, nil
}

func extractFixturesFromComposite(detector string, lit *ast.CompositeLit, env map[string]string) ([]testFixture, error) {
	var fixtures []testFixture
	for _, elt := range lit.Elts {
		caseLit, ok := elt.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("test case was not a composite literal")
		}

		var name string
		var input string
		var wants []string
		for _, field := range caseLit.Elts {
			kv, ok := field.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}

			switch key.Name {
			case "name":
				value, ok := evalString(kv.Value, env)
				if !ok {
					return nil, fmt.Errorf("unsupported test name expression")
				}
				name = value
			case "input":
				value, ok := evalString(kv.Value, env)
				if !ok {
					return nil, fmt.Errorf("unsupported input expression")
				}
				input = value
			case "want":
				values, ok := evalStringSlice(kv.Value, env)
				if !ok {
					return nil, fmt.Errorf("unsupported want expression")
				}
				wants = values
			}
		}

		if name == "" || input == "" {
			return nil, fmt.Errorf("fixture missing name or input")
		}
		if len(wants) == 0 {
			continue
		}

		fixtures = append(fixtures, testFixture{
			Detector: detector,
			Name:     name,
			Input:    input,
			Wants:    wants,
		})
	}
	return fixtures, nil
}

func evalStringSlice(expr ast.Expr, env map[string]string) ([]string, bool) {
	if ident, ok := expr.(*ast.Ident); ok && ident.Name == "nil" {
		return nil, true
	}

	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	values := make([]string, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		value, ok := evalString(elt, env)
		if !ok {
			return nil, false
		}
		values = append(values, value)
	}
	return values, true
}

func evalString(expr ast.Expr, env map[string]string) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		unquoted, err := strconv.Unquote(value.Value)
		if err != nil {
			return "", false
		}
		return unquoted, true
	case *ast.Ident:
		out, ok := env[value.Name]
		return out, ok
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return "", false
		}
		left, ok := evalString(value.X, env)
		if !ok {
			return "", false
		}
		right, ok := evalString(value.Y, env)
		if !ok {
			return "", false
		}
		return left + right, true
	case *ast.ParenExpr:
		return evalString(value.X, env)
	case *ast.CallExpr:
		selector, ok := value.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" || selector.Sel.Name != "Sprintf" || len(value.Args) == 0 {
			return "", false
		}
		format, ok := evalString(value.Args[0], env)
		if !ok {
			return "", false
		}
		args := make([]any, 0, len(value.Args)-1)
		for _, arg := range value.Args[1:] {
			rendered, ok := evalFormatArg(arg, env)
			if !ok {
				return "", false
			}
			args = append(args, rendered)
		}
		return fmt.Sprintf(format, args...), true
	default:
		return "", false
	}
}

func evalFormatArg(expr ast.Expr, env map[string]string) (any, bool) {
	if str, ok := evalString(expr, env); ok {
		return str, true
	}

	switch value := expr.(type) {
	case *ast.BasicLit:
		switch value.Kind {
		case token.INT:
			n, err := strconv.Atoi(value.Value)
			if err != nil {
				return nil, false
			}
			return n, true
		}
	case *ast.Ident:
		switch value.Name {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}

	return nil, false
}

func writeFixtures(outPath, repo, commit string, fixtures []testFixture) {
	sort.Slice(fixtures, func(i, j int) bool {
		if fixtures[i].Detector != fixtures[j].Detector {
			return fixtures[i].Detector < fixtures[j].Detector
		}
		return fixtures[i].Name < fixtures[j].Name
	})

	var buf bytes.Buffer
	fmt.Fprintln(&buf, "// @generated by scripts/sync_trufflehog_pattern_fixtures.go")
	fmt.Fprintf(&buf, "// source: %s @ %s\n\n", repo, commit)
	fmt.Fprintf(&buf, "pub const TRUFFLEHOG_PATTERN_FIXTURE_SOURCE_COMMIT: &str = %s;\n\n", rustString(commit))
	fmt.Fprintln(&buf, "pub static TRUFFLEHOG_PATTERN_FIXTURES: &[(&str, &str, &str, &[&str])] = &[")
	for _, fixture := range fixtures {
		fmt.Fprintf(&buf, "    (%s, %s, %s, &[", rustString(fixture.Detector), rustString(fixture.Name), rustString(fixture.Input))
		for i, want := range fixture.Wants {
			if i > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(rustString(want))
		}
		fmt.Fprintln(&buf, "]),")
	}
	fmt.Fprintln(&buf, "];")

	must(os.WriteFile(outPath, buf.Bytes(), 0o644))
}

func rustString(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "\\r")
	value = strings.ReplaceAll(value, "\t", "\\t")
	return `"` + value + `"`
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must(cmd.Run())
}

func output(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	must(err)
	return string(out)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
