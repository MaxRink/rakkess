package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

// Run the real entry point in a fresh process so Cobra flags and client caches
// cannot leak between invocations.
func TestCLIProcess(_ *testing.T) {
	if os.Getenv("RAKKESS_TEST_CLI") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	os.Args = append([]string{"rakkess"}, os.Args[separator+1:]...)
	main()
	os.Exit(0)
}

func TestCLI(t *testing.T) {
	for _, tt := range []struct {
		name              string
		args              []string
		want              []string
		subjects          []string
		reviewError       bool
		discoveryError    bool
		wantError         bool
		interrupt         bool
		evaluationError   bool
		evaluationAllowed bool
		extraResources    string
	}{
		{name: "interrupt cancels pending reviews", interrupt: true, want: []string{"nodes ERR n/a", "pods ERR ERR"}, subjects: []string{""}},
		{name: "matrix", want: []string{"nodes yes n/a", "pods yes no"}, subjects: []string{""}},
		{name: "namespaced service account", args: []string{"-n", "team", "--sa", "reader"}, want: []string{"pods yes no"}, subjects: []string{"system:serviceaccount:team:reader"}},
		{name: "diff service accounts", args: []string{"--sa", "team:reader", "--diff-with", "sa=team:writer"}, want: []string{"pods n/a yes"}, subjects: []string{"system:serviceaccount:team:reader", "system:serviceaccount:team:writer"}},
		{name: "replace impersonated groups", args: []string{"--as", "tester", "--as-group", "editors", "--diff-with", "as-group=viewers"}, want: []string{"pods n/a no"}, subjects: []string{"tester+editors", "tester+viewers"}},
		{name: "repeated replacement groups", args: []string{"--as", "tester", "--as-group", "editors", "--diff-with", "as-group=viewers", "--diff-with", "as-group=auditors"}, want: []string{"pods n/a no"}, subjects: []string{"tester+editors", "tester+viewers,auditors"}},
		{name: "clear service account", args: []string{"--as", "tester", "--sa", "team:writer", "--diff-with", "sa="}, want: []string{"pods n/a no"}, subjects: []string{"system:serviceaccount:team:writer", "tester"}},
		{name: "clear service account and change user", args: []string{"--sa", "team:writer", "--diff-with", "sa=", "--diff-with", "as=another"}, want: []string{"pods n/a no"}, subjects: []string{"another", "system:serviceaccount:team:writer"}},
		{name: "evaluation error denied", evaluationError: true, want: []string{"nodes yes n/a", "pods yes ERR"}, subjects: []string{""}},
		{name: "evaluation error allowed", evaluationError: true, evaluationAllowed: true, want: []string{"nodes yes n/a", "pods yes ERR"}, subjects: []string{""}},
		{name: "evaluation error in diff", evaluationError: true, args: []string{"--sa", "team:reader", "--diff-with", "sa=team:writer"}, want: []string{"pods n/a ERR"}, subjects: []string{"system:serviceaccount:team:reader", "system:serviceaccount:team:writer"}},
		{name: "unqueried verbs remain unknown", args: []string{"--diff-with", "verbs=create"}, want: []string{"nodes ERR n/a", "pods ERR n/a"}, subjects: []string{""}},
		{name: "right-only resource", extraResources: "writer", args: []string{"--sa", "team:reader", "--diff-with", "sa=team:writer"}, want: []string{"configmaps ERR ERR", "pods n/a yes"}, subjects: []string{"system:serviceaccount:team:reader", "system:serviceaccount:team:writer"}},
		{name: "left-only resource", extraResources: "reader", args: []string{"--sa", "team:reader", "--diff-with", "sa=team:writer"}, want: []string{"configmaps ERR ERR", "pods n/a yes"}, subjects: []string{"system:serviceaccount:team:reader", "system:serviceaccount:team:writer"}},
		{name: "review error in matrix", reviewError: true, want: []string{"nodes yes n/a", "pods yes ERR"}, subjects: []string{""}},
		{name: "review error in diff", reviewError: true, args: []string{"--sa", "team:reader", "--diff-with", "sa=team:writer"}, want: []string{"pods n/a ERR"}, subjects: []string{"system:serviceaccount:team:reader", "system:serviceaccount:team:writer"}},
		{name: "discovery failure", discoveryError: true, wantError: true},
		{name: "invalid diff service account", args: []string{"--diff-with", "sa=unqualified"}, wantError: true, subjects: []string{""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.interrupt && runtime.GOOS == "windows" {
				t.Skip("Windows does not support sending os.Interrupt")
			}
			reviewsStarted := make(chan struct{})
			var reviewReady sync.Once
			var mu sync.Mutex
			var subjects []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api":
					if tt.discoveryError {
						http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`, http.StatusForbidden)
						return
					}
					fmt.Fprint(w, `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`)
				case "/apis":
					fmt.Fprint(w, `{"kind":"APIGroupList","apiVersion":"v1","groups":[]}`)
				case "/api/v1":
					extra := ""
					if tt.extraResources != "" && strings.HasSuffix(r.Header.Get("Impersonate-User"), ":"+tt.extraResources) {
						extra = `,{"name":"configmaps","kind":"ConfigMap","namespaced":true,"verbs":["create"]}`
					}
					fmt.Fprintf(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[{"name":"pods","kind":"Pod","namespaced":true,"verbs":["list","create"]},{"name":"nodes","kind":"Node","namespaced":false,"verbs":["list"]}%s]}`, extra)
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					var review authorizationv1.SelfSubjectAccessReview
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						http.Error(w, "read review", 400)
						return
					}
					if _, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, &review); err != nil {
						t.Error(err)
						http.Error(w, "bad review", 400)
						return
					}
					a := review.Spec.ResourceAttributes
					if a == nil {
						t.Error("missing resource attributes")
						http.Error(w, "missing attributes", 400)
						return
					}
					wantNamespace := ""
					if slices.Contains(tt.args, "-n") {
						wantNamespace = "team"
					}
					if a.Namespace != wantNamespace {
						t.Errorf("review namespace = %q, want %q", a.Namespace, wantNamespace)
					}
					user := r.Header.Get("Impersonate-User")
					mu.Lock()
					identity := user
					if groups := r.Header.Values("Impersonate-Group"); len(groups) > 0 {
						identity += "+" + strings.Join(groups, ",")
					}
					subjects = append(subjects, identity)
					mu.Unlock()
					if tt.interrupt {
						reviewReady.Do(func() { close(reviewsStarted) })
						<-r.Context().Done()
						return
					}
					if tt.reviewError && a.Resource == "pods" && a.Verb == "create" && user != "system:serviceaccount:team:writer" {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"InternalError","message":"review unavailable","code":500}`)
						return
					}
					review.Status.Allowed = a.Verb == "list" || user == "system:serviceaccount:team:writer" || slices.Contains(r.Header.Values("Impersonate-Group"), "editors")
					if tt.evaluationError && a.Resource == "pods" && a.Verb == "create" {
						review.Status.EvaluationError = "authorizer unavailable"
						review.Status.Allowed = tt.evaluationAllowed
					}
					if err := json.NewEncoder(w).Encode(&review); err != nil {
						t.Error(err)
					}
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			dir := t.TempDir()
			kubeconfig := filepath.Join(dir, "config")
			config := fmt.Sprintf(`{"apiVersion":"v1","kind":"Config","clusters":[{"name":"test","cluster":{"server":%q}}],"contexts":[{"name":"test","context":{"cluster":"test"}}],"current-context":"test"}`, server.URL)
			if err := os.WriteFile(kubeconfig, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			args := []string{"-test.run=^TestCLIProcess$", "--", "--kubeconfig", kubeconfig, "--cache-dir", dir, "--verbs", "list,create", "-o", "ascii-table"}
			process := exec.CommandContext(ctx, os.Args[0], append(args, tt.args...)...) // #nosec G204 G702 -- executes this test binary with table-defined arguments.
			process.Env = append(os.Environ(), "RAKKESS_TEST_CLI=1")
			var stdout, stderr bytes.Buffer
			process.Stdout = &stdout
			process.Stderr = &stderr
			var err error
			if tt.interrupt {
				if err = process.Start(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-reviewsStarted:
					if err = process.Process.Signal(os.Interrupt); err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("CLI did not start an access review")
				}
				err = process.Wait()
			} else {
				err = process.Run()
			}
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, want error %v; stderr: %s", err, tt.wantError, &stderr)
			}
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			if tt.wantError {
				if strings.Contains(stdout.String(), "NAME") {
					t.Fatalf("printed matrix despite error: %s", &stdout)
				}
			} else {
				var rows []string
				for _, line := range strings.Split(stdout.String(), "\n") {
					fields := strings.Fields(line)
					if len(fields) > 0 && (fields[0] == "pods" || fields[0] == "nodes" || fields[0] == "configmaps") {
						rows = append(rows, strings.Join(fields, " "))
					}
				}
				if !slices.Equal(rows, tt.want) {
					t.Errorf("rows = %q, want %q; stderr: %s", rows, tt.want, &stderr)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			slices.Sort(subjects)
			subjects = slices.Compact(subjects)
			if !slices.Equal(subjects, tt.subjects) {
				t.Errorf("impersonated subjects = %q, want %q", subjects, tt.subjects)
			}
		})
	}
}
