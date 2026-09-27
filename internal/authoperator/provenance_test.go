package authoperator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

func TestCollect(t *testing.T) {
	for _, tt := range []struct {
		name, username, namespace, deny                           string
		groups                                                    []string
		origins                                                   int
		incomplete                                                bool
		badSelector, stale, explicit, localRole, cluster, removed bool
	}{
		{name: "group and aggregate sources", username: "alice", groups: []string{"developers"}, namespace: "payments", origins: 3},
		{name: "service account", username: "system:serviceaccount:payments:reader", namespace: "payments", origins: 3},
		{name: "unrelated identity", username: "outsider", namespace: "payments"},
		{name: "protected namespace excluded", username: "alice", groups: []string{"developers"}, namespace: "protected"},
		{name: "OR alternate selector", username: "alice", groups: []string{"developers"}, namespace: "other", origins: 3},
		{name: "all requirements must match", username: "alice", groups: []string{"developers"}, namespace: "silver"},
		{name: "namespaced binding is not cluster access", username: "alice", groups: []string{"developers"}},
		{name: "cluster binding", username: "alice", groups: []string{"developers"}, cluster: true, origins: 3},
		{name: "forbidden bindings", username: "alice", groups: []string{"developers"}, namespace: "payments", deny: "rolebindings", incomplete: true, origins: 3},
		{name: "unknown namespaces", username: "alice", groups: []string{"developers"}, namespace: "payments", deny: "namespaces", incomplete: true, origins: 3},
		{name: "identity unavailable", username: "alice", namespace: "payments", deny: "selfsubjectreviews", incomplete: true},
		{name: "invalid selector is unknown", username: "alice", groups: []string{"developers"}, namespace: "payments", badSelector: true, incomplete: true, origins: 3},
		{name: "explicit namespace overrides selector", username: "alice", groups: []string{"developers"}, namespace: "payments", badSelector: true, explicit: true, origins: 3},
		{name: "observed role differs from desired", username: "alice", groups: []string{"developers"}, namespace: "payments", stale: true, origins: 3},
		{name: "removed desired binding entry", username: "alice", groups: []string{"developers"}, namespace: "payments", removed: true, incomplete: true},
		{name: "namespaced generated Role", username: "alice", groups: []string{"developers"}, namespace: "payments", localRole: true, origins: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resources := provenanceResources()
			if tt.badSelector {
				resources["binddefinitions"] = strings.ReplaceAll(resources["binddefinitions"], "DoesNotExist", "Bogus")
			}
			if tt.explicit {
				resources["binddefinitions"] = strings.ReplaceAll(resources["binddefinitions"], `"namespaceSelector":`, `"namespace":"payments","namespaceSelector":`)
			}
			if tt.stale {
				resources["binddefinitions"] = strings.ReplaceAll(resources["binddefinitions"], `["aggregate"]`, `["new-target"]`)
			}
			if tt.localRole {
				resources["binddefinitions"] = strings.ReplaceAll(resources["binddefinitions"], `"clusterRoleRefs":["aggregate"]`, `"roleRefs":["local-reader"]`)
				resources["rolebindings"] = strings.ReplaceAll(resources["rolebindings"], `"kind":"ClusterRole","name":"aggregate"`, `"kind":"Role","name":"local-reader"`)
			}
			if tt.cluster {
				resources["binddefinitions"] = strings.ReplaceAll(resources["binddefinitions"], `"roleBindings":[{`, `"clusterRoleBindings":{"clusterRoleRefs":["aggregate"]},"roleBindings":[{`)
				resources["clusterrolebindings"] = strings.ReplaceAll(resources["rolebindings"], `"namespace":"payments",`, "")
			}
			if tt.removed {
				resources["binddefinitions"] = `[]`
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
				if name == tt.deny {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}`))
					return
				}
				if name == "selfsubjectreviews" {
					value := map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview", "status": map[string]any{"userInfo": map[string]any{"username": tt.username, "groups": tt.groups}}}
					if err := json.NewEncoder(w).Encode(value); err != nil {
						t.Error(err)
					}
					return
				}
				body, ok := resources[name]
				if !ok {
					t.Errorf("unexpected request %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				// All dynamic resources return ordinary Kubernetes list responses.
				if _, err := w.Write([]byte(`{"apiVersion":"v1","kind":"List","items":` + body + `}`)); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			report := Collect(context.Background(), &rest.Config{Host: server.URL}, tt.namespace)
			if report.Complete == tt.incomplete || !report.Advisory || len(report.Origins) != tt.origins {
				t.Fatalf("report = %#v", report)
			}
			if (len(report.Errors) > 0) != tt.incomplete {
				t.Fatalf("errors = %v", report.Errors)
			}
			for _, origin := range report.Origins {
				if strings.Contains(origin.Name, "unrelated") {
					t.Errorf("unrelated origin: %#v", origin)
				}
				if origin.Kind == "RoleDefinition" && origin.QueriedNamespaceMatch != nil {
					t.Error("RoleDefinition has a binding selector result")
				}
				if origin.Kind == "BindDefinition" {
					if (tt.badSelector && !tt.explicit) || tt.deny == "namespaces" {
						if origin.QueriedNamespaceMatch != nil {
							t.Error("unknown selector result became definite")
						}
					}
					if !tt.incomplete {
						if len(origin.Generated) == 0 {
							t.Errorf("observed binding not linked: %#v", origin)
						}
						for _, binding := range origin.Generated {
							if binding.RoleRef == nil {
								t.Error("missing observed role reference")
							}
						}
					}
				}
			}
			if tt.origins == 3 {
				var aggregate *Generated
				for i := range report.Roles {
					if report.Roles[i].Name == "aggregate" {
						aggregate = &report.Roles[i]
					}
				}
				if aggregate == nil || !slices.Equal(aggregate.AggregateSources, []string{"leaf"}) {
					t.Fatalf("observed aggregation missing/wrong: %#v", aggregate)
				}
			}
		})
	}
}

func provenanceResources() map[string]string {
	return map[string]string{
		"binddefinitions": `[
 {"metadata":{"name":"team-bind"},"spec":{"targetName":"team","subjects":[{"kind":"Group","name":"developers"},{"kind":"ServiceAccount","namespace":"payments","name":"reader"}],"roleBindings":[{"clusterRoleRefs":["aggregate"],"namespaceSelector":[{"matchLabels":{"team":"payments"},"matchExpressions":[{"key":"protected","operator":"DoesNotExist"}]},{"matchLabels":{"tier":"gold"}}]}]}},
 {"metadata":{"name":"unrelated-bind"},"spec":{"subjects":[{"kind":"User","name":"someone-else"}],"clusterRoleBindings":{"clusterRoleRefs":["unrelated"]}}} ]`,
		"roledefinitions": `[
 {"metadata":{"name":"aggregate-definition"},"spec":{"targetRole":"ClusterRole","targetName":"aggregate","aggregateFrom":{"clusterRoleSelectors":[{"matchLabels":{"leaf":"yes"}}]}}},
 {"metadata":{"name":"leaf-definition"},"spec":{"targetRole":"ClusterRole","targetName":"leaf"}},
 {"metadata":{"name":"local-definition"},"spec":{"targetRole":"Role","targetNamespace":"payments","targetName":"local-reader"}},
 {"metadata":{"name":"unrelated-namespace"},"spec":{"targetRole":"Role","targetNamespace":"other","targetName":"local-reader"}},
 {"metadata":{"name":"unrelated-kind"},"spec":{"targetRole":"ClusterRole","targetName":"local-reader"}},
 {"metadata":{"name":"unrelated-role"},"spec":{"targetRole":"ClusterRole","targetName":"unrelated"}} ]`,
		"clusterroles": `[
 {"metadata":{"name":"aggregate","labels":{"leaf":"yes"},"annotations":{"authorization.t-caas.telekom.com/source-kind":"RoleDefinition","authorization.t-caas.telekom.com/source-name":"aggregate-definition"}},"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"leaf":"yes"}}]}},
 {"metadata":{"name":"leaf","labels":{"leaf":"yes"},"annotations":{"authorization.t-caas.telekom.com/source-kind":"RoleDefinition","authorization.t-caas.telekom.com/source-name":"leaf-definition"}}} ]`,
		"roles": `[{"metadata":{"name":"local-reader","namespace":"payments","annotations":{"authorization.t-caas.telekom.com/source-kind":"RoleDefinition","authorization.t-caas.telekom.com/source-name":"local-definition"}}}]`,
		"rolebindings": `[
 {"metadata":{"name":"opaque-hashed-binding","namespace":"payments","ownerReferences":[{"apiVersion":"authorization.t-caas.telekom.com/v1alpha1","kind":"BindDefinition","name":"team-bind","uid":"owner"}],"annotations":{"authorization.t-caas.telekom.com/source-kind":"BindDefinition","authorization.t-caas.telekom.com/source-name":"team-bind"}},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"aggregate"},"subjects":[{"kind":"Group","name":"developers"},{"kind":"ServiceAccount","namespace":"payments","name":"reader"}]},
 {"metadata":{"name":"alternate-binding","namespace":"other","annotations":{"authorization.t-caas.telekom.com/source-kind":"BindDefinition","authorization.t-caas.telekom.com/source-name":"team-bind"}},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"aggregate"},"subjects":[{"kind":"Group","name":"developers"}]} ]`,
		"clusterrolebindings": `[]`,
		"namespaces": `[
 {"metadata":{"name":"payments","labels":{"team":"payments"}}},
 {"metadata":{"name":"protected","labels":{"team":"payments","protected":"true"}}},
 {"metadata":{"name":"other","labels":{"tier":"gold"}}},
 {"metadata":{"name":"silver","labels":{"tier":"silver"}}} ]`,
	}
}
