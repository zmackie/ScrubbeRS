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
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const defaultRepo = "https://github.com/trufflesecurity/trufflehog.git"
const minInlineFragmentLen = 6

var residualTokenPattern = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_:/.=+%@~-]{19,}`)

type testFixture struct {
	Detector string
	Name     string
	Input    string
	Wants    []string
}

type bindingEnv struct {
	Strings map[string]string
	Slices  map[string][]string
}

func main() {
	repo := flag.String("repo", defaultRepo, "TruffleHog git repository to clone")
	ref := flag.String("ref", "", "Optional branch, tag, or commit to fetch instead of repo HEAD")
	out := flag.String("out", "tests/generated_trufflehog_pattern_fixtures.rs", "Output Rust fixture file")
	flag.Parse()

	tmpDir, err := os.MkdirTemp("", "trufflehog-pattern-fixtures-")
	must(err)
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "trufflehog")
	fetchRepo(repoDir, *repo, *ref)
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

	baseEnv, err := collectBindings(file)
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

		testsLit, env, err := findTestsCompositeLit(fn.Body, baseEnv)
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

func findTestsCompositeLit(body *ast.BlockStmt, baseEnv bindingEnv) (*ast.CompositeLit, bindingEnv, error) {
	env := cloneEnv(baseEnv)
	for _, stmt := range body.List {
		if updated := applyBindingStmt(stmt, env); updated {
			continue
		}
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
			return nil, env, fmt.Errorf("tests assignment was not a composite literal")
		}
		return lit, env, nil
	}
	return nil, env, nil
}

func cloneEnv(src bindingEnv) bindingEnv {
	env := bindingEnv{
		Strings: make(map[string]string, len(src.Strings)),
		Slices:  make(map[string][]string, len(src.Slices)),
	}
	for key, value := range src.Strings {
		env.Strings[key] = value
	}
	for key, values := range src.Slices {
		env.Slices[key] = append([]string(nil), values...)
	}
	return env
}

func applyBindingStmt(stmt ast.Stmt, env bindingEnv) bool {
	switch value := stmt.(type) {
	case *ast.AssignStmt:
		if len(value.Lhs) != len(value.Rhs) {
			return false
		}
		updated := false
		for i, lhs := range value.Lhs {
			name, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			if str, ok := evalString(value.Rhs[i], env); ok {
				env.Strings[name.Name] = str
				delete(env.Slices, name.Name)
				updated = true
				continue
			}
			if slice, ok := evalStringSlice(value.Rhs[i], env); ok {
				env.Slices[name.Name] = slice
				delete(env.Strings, name.Name)
				updated = true
			}
		}
		return updated
	case *ast.DeclStmt:
		gen, ok := value.Decl.(*ast.GenDecl)
		if !ok || (gen.Tok != token.VAR && gen.Tok != token.CONST) {
			return false
		}
		updated := false
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if len(valueSpec.Values) == 0 {
					continue
				}
				exprIndex := min(i, len(valueSpec.Values)-1)
				if str, ok := evalString(valueSpec.Values[exprIndex], env); ok {
					env.Strings[name.Name] = str
					delete(env.Slices, name.Name)
					updated = true
					continue
				}
				if slice, ok := evalStringSlice(valueSpec.Values[exprIndex], env); ok {
					env.Slices[name.Name] = slice
					delete(env.Strings, name.Name)
					updated = true
				}
			}
		}
		return updated
	default:
		return false
	}
}

func collectBindings(file *ast.File) (bindingEnv, error) {
	env := bindingEnv{
		Strings: make(map[string]string),
		Slices:  make(map[string][]string),
	}
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
					if len(valueSpec.Values) == 0 {
						continue
					}
					exprIndex := min(i, len(valueSpec.Values)-1)
					if _, exists := env.Strings[name.Name]; !exists {
						if value, ok := evalString(valueSpec.Values[exprIndex], env); ok {
							env.Strings[name.Name] = value
							progress = true
							continue
						}
					}
					if _, exists := env.Slices[name.Name]; !exists {
						if values, ok := evalStringSlice(valueSpec.Values[exprIndex], env); ok {
							env.Slices[name.Name] = values
							progress = true
						}
					}
				}
			}
		}
	}

	return env, nil
}

func extractFixturesFromComposite(detector string, lit *ast.CompositeLit, env bindingEnv) ([]testFixture, error) {
	var fixtures []testFixture
	for idx, elt := range lit.Elts {
		caseLit, ok := elt.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("test case was not a composite literal")
		}

		var name string
		var input string
		var wants []string
		var match string
		var shouldMatch bool
		var hasShouldMatch bool
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
			case "input", "data":
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
			case "match":
				value, ok := evalString(kv.Value, env)
				if !ok {
					return nil, fmt.Errorf("unsupported match expression")
				}
				match = value
			case "shouldMatch":
				value, ok := evalBool(kv.Value)
				if !ok {
					return nil, fmt.Errorf("unsupported shouldMatch expression")
				}
				shouldMatch = value
				hasShouldMatch = true
			}
		}

		if name == "" {
			name = fmt.Sprintf("case_%d", idx+1)
		}
		if input == "" {
			return nil, fmt.Errorf("fixture missing input")
		}
		if len(wants) == 0 && hasShouldMatch && shouldMatch {
			if match != "" {
				wants = []string{match}
			} else {
				wants = []string{input}
			}
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

func evalStringSlice(expr ast.Expr, env bindingEnv) ([]string, bool) {
	if ident, ok := expr.(*ast.Ident); ok && ident.Name == "nil" {
		return nil, true
	}
	if ident, ok := expr.(*ast.Ident); ok {
		values, found := env.Slices[ident.Name]
		return values, found
	}

	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	values := make([]string, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		if value, ok := evalString(elt, env); ok {
			values = append(values, value)
			continue
		}
		nested, ok := evalStringSlice(elt, env)
		if !ok {
			return nil, false
		}
		values = append(values, nested...)
	}
	return values, true
}

func evalString(expr ast.Expr, env bindingEnv) (string, bool) {
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
		out, ok := env.Strings[value.Name]
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
		if ident, ok := value.Fun.(*ast.Ident); ok {
			switch ident.Name {
			case "generateRandomString":
				return "ey" + strings.Repeat("A", 2001), true
			case "makeFakeTokenString":
				if len(value.Args) != 2 {
					return "", false
				}
				token, ok := evalString(value.Args[0], env)
				if !ok {
					return "", false
				}
				domain, ok := evalString(value.Args[1], env)
				if !ok {
					return "", false
				}
				return fmt.Sprintf("auth0:\n apiToken: %s \n domain: %s", token, domain), true
			}
		}
		selector, ok := value.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		switch {
		case pkg.Name == "fmt" && selector.Sel.Name == "Sprintf" && len(value.Args) > 0:
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
		case pkg.Name == "strings" && selector.Sel.Name == "TrimSpace" && len(value.Args) == 1:
			input, ok := evalString(value.Args[0], env)
			if !ok {
				return "", false
			}
			return strings.TrimSpace(input), true
		case pkg.Name == "common" && selector.Sel.Name == "GenerateRandomPassword":
			return evalGenerateRandomPassword(value.Args)
		case pkg.Name == "gofakeit" && selector.Sel.Name == "Username" && len(value.Args) == 0:
			return "fixture_user", true
		}
		return "", false
	default:
		return "", false
	}
}

func evalFormatArg(expr ast.Expr, env bindingEnv) (any, bool) {
	if str, ok := evalString(expr, env); ok {
		return str, true
	}

	if n, ok := evalInt(expr); ok {
		return n, true
	}
	if b, ok := evalBool(expr); ok {
		return b, true
	}
	return nil, false
}

func evalGenerateRandomPassword(args []ast.Expr) (string, bool) {
	if len(args) != 5 {
		return "", false
	}
	hasLower, ok := evalBool(args[0])
	if !ok {
		return "", false
	}
	hasUpper, ok := evalBool(args[1])
	if !ok {
		return "", false
	}
	hasDigits, ok := evalBool(args[2])
	if !ok {
		return "", false
	}
	hasSpecial, ok := evalBool(args[3])
	if !ok {
		return "", false
	}
	length, ok := evalInt(args[4])
	if !ok || length <= 0 {
		return "", false
	}

	var alphabet string
	if hasLower {
		alphabet += "abcxyz"
	}
	if hasUpper {
		alphabet += "ABCXYZ"
	}
	if hasDigits {
		alphabet += "0123456789"
	}
	if hasSpecial {
		alphabet += "_-!@"
	}
	if alphabet == "" {
		return "", false
	}

	var out strings.Builder
	out.Grow(length)
	for i := 0; i < length; i++ {
		out.WriteByte(alphabet[i%len(alphabet)])
	}
	return out.String(), true
}

func evalInt(expr ast.Expr) (int, bool) {
	value, ok := expr.(*ast.BasicLit)
	if !ok || value.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(value.Value)
	if err != nil {
		return 0, false
	}
	return n, true
}

func evalBool(expr ast.Expr) (bool, bool) {
	value, ok := expr.(*ast.Ident)
	if !ok {
		return false, false
	}
	switch value.Name {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func writeFixtures(outPath, repo, commit string, fixtures []testFixture) {
	fixtures = sanitizeFixtures(fixtures)
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
	run("rustfmt", outPath)
}

func sanitizeFixtures(fixtures []testFixture) []testFixture {
	sanitized := make([]testFixture, 0, len(fixtures))
	for _, fixture := range fixtures {
		sanitized = append(sanitized, sanitizeFixture(fixture))
	}
	return sanitized
}

func sanitizeFixture(fixture testFixture) testFixture {
	fragments := inlineSecretFragments(fixture.Input, fixture.Wants)
	if len(fragments) == 0 {
		return fixture
	}

	replacements := make(map[string]string, len(fragments))
	for idx, fragment := range fragments {
		replacements[fragment] = safePlaceholder(len(fragment), idx)
	}

	sanitizedInput := fixture.Input
	for _, fragment := range fragments {
		sanitizedInput = strings.ReplaceAll(sanitizedInput, fragment, replacements[fragment])
	}
	sanitizedInput = sanitizeResidualTokens(sanitizedInput, len(replacements))

	sanitizedWants := make([]string, 0, len(fixture.Wants))
	for _, want := range fixture.Wants {
		wantFragments := orderedInlineFragments(fixture.Input, want)
		if len(wantFragments) == 0 {
			continue
		}

		var builder strings.Builder
		for _, fragment := range wantFragments {
			builder.WriteString(replacements[fragment])
		}
		sanitizedWants = append(sanitizedWants, builder.String())
	}

	if len(sanitizedWants) == 0 {
		sanitizedWants = make([]string, 0, len(fragments))
		for _, fragment := range fragments {
			sanitizedWants = append(sanitizedWants, replacements[fragment])
		}
	}

	return testFixture{
		Detector: fixture.Detector,
		Name:     fixture.Name,
		Input:    sanitizedInput,
		Wants:    sanitizedWants,
	}
}

func inlineSecretFragments(input string, wants []string) []string {
	var fragments []string
	for _, want := range wants {
		fragments = append(fragments, orderedInlineFragments(input, want)...)
	}
	pruneRedundantFragments(&fragments)
	return fragments
}

func orderedInlineFragments(input, want string) []string {
	var fragments []string
	for start := 0; start < len(want); start++ {
		matchedEnd := -1
		for end := len(want); end > start; end-- {
			candidate := want[start:end]
			if len(candidate) < minInlineFragmentLen {
				break
			}
			if strings.Contains(input, candidate) {
				fragments = append(fragments, candidate)
				matchedEnd = end
				break
			}
		}

		if matchedEnd >= 0 {
			start = matchedEnd - 1
		}
	}
	return fragments
}

func pruneRedundantFragments(fragments *[]string) {
	sort.Slice(*fragments, func(i, j int) bool {
		left := (*fragments)[i]
		right := (*fragments)[j]
		if len(left) != len(right) {
			return len(left) > len(right)
		}
		return left < right
	})

	deduped := (*fragments)[:0]
	for _, fragment := range *fragments {
		duplicate := false
		for _, existing := range deduped {
			if existing == fragment {
				duplicate = true
				break
			}
		}
		if !duplicate {
			deduped = append(deduped, fragment)
		}
	}

	pruned := deduped[:0]
	for _, fragment := range deduped {
		covered := false
		for _, existing := range pruned {
			if strings.Contains(existing, fragment) {
				covered = true
				break
			}
		}
		if !covered {
			pruned = append(pruned, fragment)
		}
	}

	sort.Strings(pruned)
	*fragments = pruned
}

func safePlaceholder(length, idx int) string {
	seed := fmt.Sprintf("fixture_%02d~", idx)
	if len(seed) >= length {
		return seed[:length]
	}

	var builder strings.Builder
	builder.Grow(length)
	for builder.Len() < length {
		builder.WriteString(seed)
	}
	value := builder.String()
	return value[:length]
}

func sanitizeResidualTokens(input string, seed int) string {
	next := seed
	return residualTokenPattern.ReplaceAllStringFunc(input, func(token string) string {
		if strings.Contains(token, "fixture_") {
			return token
		}
		if !hasASCIIAlpha(token) || !hasASCIIDigit(token) {
			return token
		}

		replacement := safePlaceholder(len(token), next)
		next++
		return replacement
	})
}

func hasASCIIAlpha(input string) bool {
	for i := 0; i < len(input); i++ {
		b := input[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			return true
		}
	}
	return false
}

func hasASCIIDigit(input string) bool {
	for i := 0; i < len(input); i++ {
		if input[i] >= '0' && input[i] <= '9' {
			return true
		}
	}
	return false
}

func rustString(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "\\r")
	value = strings.ReplaceAll(value, "\t", "\\t")
	return `"` + value + `"`
}

func fetchRepo(repoDir, repo, ref string) {
	if ref == "" {
		run("git", "clone", "--depth", "1", repo, repoDir)
		return
	}

	run("git", "init", repoDir)
	run("git", "-C", repoDir, "remote", "add", "origin", repo)
	run("git", "-C", repoDir, "fetch", "--depth", "1", "origin", ref)
	run("git", "-C", repoDir, "checkout", "--detach", "FETCH_HEAD")
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
