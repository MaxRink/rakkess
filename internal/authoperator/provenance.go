// Package authoperator reports provenance without making authorization decisions.
package authoperator

import (
	"context"
	"fmt"
	"slices"
	"sort"

	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

const (
	group                  = "authorization.t-caas.telekom.com"
	clusterRoleKind        = "ClusterRole"
	clusterRoleBindingKind = "ClusterRoleBinding"
)

// Report is advisory configuration and observed RBAC, never an access decision.
type Report struct {
	Complete  bool        `json:"complete"`
	Advisory  bool        `json:"advisory"`
	Errors    []string    `json:"errors,omitempty"`
	Username  string      `json:"username,omitempty"`
	Groups    []string    `json:"groups,omitempty"`
	Namespace string      `json:"namespace,omitempty"`
	Origins   []Origin    `json:"origins,omitempty"`
	Roles     []Generated `json:"roles,omitempty"`
}

type Origin struct {
	Kind                  string                 `json:"kind"`
	Name                  string                 `json:"name"`
	TargetName            string                 `json:"targetName,omitempty"`
	TargetRole            string                 `json:"targetRole,omitempty"`
	BindingType           string                 `json:"bindingType,omitempty"`
	Namespace             string                 `json:"namespace,omitempty"`
	Subjects              []rbacv1.Subject       `json:"subjects,omitempty"`
	RoleRefs              []string               `json:"roleRefs,omitempty"`
	ClusterRoleRefs       []string               `json:"clusterRoleRefs,omitempty"`
	NamespaceSelectors    []metav1.LabelSelector `json:"namespaceSelectors,omitempty"`
	MatchingNamespaces    []string               `json:"matchingNamespaces,omitempty"`
	QueriedNamespaceMatch *bool                  `json:"queriedNamespaceMatch,omitempty"`
	AggregateSelectors    []metav1.LabelSelector `json:"aggregateSelectors,omitempty"`
	Generated             []Generated            `json:"generated,omitempty"`
}

type Generated struct {
	Kind               string                 `json:"kind"`
	Name               string                 `json:"name"`
	Namespace          string                 `json:"namespace,omitempty"`
	RoleRef            *rbacv1.RoleRef        `json:"roleRef,omitempty"`
	Subjects           []rbacv1.Subject       `json:"subjects,omitempty"`
	AggregateSelectors []metav1.LabelSelector `json:"aggregateSelectors,omitempty"`
	AggregateSources   []string               `json:"aggregateSources,omitempty"`
}

type binding struct {
	Namespace          string                 `json:"namespace"`
	NamespaceSelectors []metav1.LabelSelector `json:"namespaceSelector"`
	RoleRefs           []string               `json:"roleRefs"`
	ClusterRoleRefs    []string               `json:"clusterRoleRefs"`
}

// Only fields needed for provenance are decoded; Kubernetes owns the CRD schema.
type definition struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     struct {
		TargetName          string                  `json:"targetName"`
		TargetRole          string                  `json:"targetRole"`
		TargetNamespace     string                  `json:"targetNamespace"`
		Subjects            []rbacv1.Subject        `json:"subjects"`
		RoleBindings        []binding               `json:"roleBindings"`
		ClusterRoleBindings *binding                `json:"clusterRoleBindings"`
		AggregateFrom       *rbacv1.AggregationRule `json:"aggregateFrom"`
	} `json:"spec"`
}

type observed struct {
	Metadata        metav1.ObjectMeta       `json:"metadata"`
	RoleRef         *rbacv1.RoleRef         `json:"roleRef"`
	Subjects        []rbacv1.Subject        `json:"subjects"`
	AggregationRule *rbacv1.AggregationRule `json:"aggregationRule"`
	Kind            string                  `json:"kind"`
}

type roleKey struct{ kind, namespace, name string }

func (r *Report) problem(err error) {
	r.Complete = false
	r.Errors = append(r.Errors, err.Error())
}

// Collect uses the same credentials and impersonation as the access reviews.
// Missing permissions, definitions or identity information remain incomplete.
func Collect(ctx context.Context, cfg *rest.Config, namespace string) Report {
	report := Report{Complete: true, Advisory: true, Namespace: namespace}
	client, err := authenticationclient.NewForConfig(cfg)
	if err != nil {
		report.problem(err)
		return report
	}
	identity, err := client.SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		report.problem(fmt.Errorf("resolve current identity: %w", err))
		return report
	}
	if identity.Status.UserInfo.Username == "" {
		report.problem(fmt.Errorf("current identity response has no username"))
		return report
	}
	report.Username, report.Groups = identity.Status.UserInfo.Username, identity.Status.UserInfo.Groups
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		report.problem(err)
		return report
	}

	// ClusterRoles include aggregation inputs that may be managed by another controller.
	list := func(apiGroup, version, resource string, out interface{}, managedOnly bool) {
		selector := ""
		if managedOnly {
			selector = "app.kubernetes.io/managed-by=auth-operator"
		}
		items, err := dyn.Resource(schema.GroupVersionResource{Group: apiGroup, Version: version, Resource: resource}).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			report.problem(fmt.Errorf("list %s: %w", resource, err))
			return
		}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(items.UnstructuredContent(), out); err != nil {
			report.problem(fmt.Errorf("decode %s: %w", resource, err))
		}
	}
	var bindDefs, roleDefs struct {
		Items []definition `json:"items"`
	}
	list(group, "v1alpha1", "binddefinitions", &bindDefs, false)
	list(group, "v1alpha1", "roledefinitions", &roleDefs, false)
	var namespaceList struct {
		Items []struct {
			Metadata metav1.ObjectMeta `json:"metadata"`
		} `json:"items"`
	}
	list("", "v1", "namespaces", &namespaceList, false)
	namespaceLabels := map[string]map[string]string{}
	for _, ns := range namespaceList.Items {
		namespaceLabels[ns.Metadata.Name] = ns.Metadata.Labels
	}
	if namespace != "" {
		if _, found := namespaceLabels[namespace]; !found {
			report.problem(fmt.Errorf("namespace %q was not observed; selector match is unknown", namespace))
		}
	}
	var objects []observed
	for _, item := range []struct {
		resource, kind string
		managed        bool
	}{
		{"clusterroles", clusterRoleKind, false}, {"roles", "Role", true},
		{"clusterrolebindings", clusterRoleBindingKind, true}, {"rolebindings", "RoleBinding", true},
	} {
		var result struct {
			Items []observed `json:"items"`
		}
		list(rbacv1.GroupName, "v1", item.resource, &result, item.managed)
		for _, obj := range result.Items {
			obj.Kind = item.kind
			objects = append(objects, obj)
		}
	}
	used := map[roleKey]bool{}
	for _, def := range bindDefs.Items {
		bindings := def.Spec.RoleBindings
		if def.Spec.ClusterRoleBindings != nil {
			bindings = append(slices.Clone(bindings), *def.Spec.ClusterRoleBindings)
		}
		for i, b := range bindings {
			kind := "RoleBinding"
			if i >= len(def.Spec.RoleBindings) {
				kind = clusterRoleBindingKind
			}
			origin := Origin{Kind: "BindDefinition", Name: def.Metadata.Name, TargetName: def.Spec.TargetName, BindingType: kind, Namespace: b.Namespace, Subjects: def.Spec.Subjects, RoleRefs: b.RoleRefs, ClusterRoleRefs: b.ClusterRoleRefs, NamespaceSelectors: b.NamespaceSelectors}
			relevant := subjectMatches(def.Spec.Subjects, report.Username, report.Groups)
			for _, obj := range objects {
				if obj.Kind != kind || !ownedBy(obj, "BindDefinition", def.Metadata.Name) || (!bindingRefMatches(obj, b) && !subjectMatches(obj.Subjects, report.Username, report.Groups)) {
					continue
				}
				if kind == "RoleBinding" && namespace != "" && obj.Metadata.Namespace != namespace {
					continue
				}
				if subjectMatches(obj.Subjects, report.Username, report.Groups) {
					relevant = true
				}
				origin.Generated = append(origin.Generated, describe(obj))
			}
			if !relevant {
				continue
			}
			origin.QueriedNamespaceMatch = matchNamespace(&report, b, kind, namespace, namespaceLabels, &origin.MatchingNamespaces)
			// A RoleBinding cannot grant a cluster-wide/all-namespaces review. An
			// observed binding is retained if reconciliation differs from desired state.
			if kind == "RoleBinding" && namespace == "" {
				continue
			}
			if origin.QueriedNamespaceMatch != nil && !*origin.QueriedNamespaceMatch && len(origin.Generated) == 0 {
				continue
			}
			report.Origins = append(report.Origins, origin)
			for _, ref := range b.RoleRefs {
				used[roleKey{"Role", namespace, ref}] = true
			}
			for _, ref := range b.ClusterRoleRefs {
				used[roleKey{clusterRoleKind, "", ref}] = true
			}
			for _, obj := range origin.Generated {
				if obj.RoleRef != nil {
					ns := ""
					if obj.RoleRef.Kind == "Role" {
						ns = obj.Namespace
					}
					used[roleKey{obj.RoleRef.Kind, ns, obj.RoleRef.Name}] = true
				}
			}
		}
	}
	// A definition can remove its last binding entry before the controller removes
	// the old binding. Do not claim complete provenance for unmatched observations.
	for _, obj := range objects {
		if obj.RoleRef == nil || !subjectMatches(obj.Subjects, report.Username, report.Groups) ||
			(obj.Kind == "RoleBinding" && (namespace == "" || obj.Metadata.Namespace != namespace)) {
			continue
		}
		found := false
		for _, origin := range report.Origins {
			for _, generated := range origin.Generated {
				if generated.Kind == obj.Kind && generated.Namespace == obj.Metadata.Namespace && generated.Name == obj.Metadata.Name {
					found = true
				}
			}
		}
		if !found {
			report.problem(fmt.Errorf("observed managed %s %s/%s has no matching definition entry", obj.Kind, obj.Metadata.Namespace, obj.Metadata.Name))
		}
	}
	// Follow observed aggregation selectors, including nested aggregating roles.
	// This describes controller inputs; the access matrix still comes from SSAR.
	aggregateSources := map[string][]string{}
	for changed := true; changed; {
		changed = false
		for _, obj := range objects {
			if obj.Kind != clusterRoleKind || !used[roleKey{clusterRoleKind, "", obj.Metadata.Name}] || obj.AggregationRule == nil {
				continue
			}
			if _, done := aggregateSources[obj.Metadata.Name]; done {
				continue
			}
			aggregateSources[obj.Metadata.Name] = []string{}
			selectors, err := compileSelectors(obj.AggregationRule.ClusterRoleSelectors)
			if err != nil {
				report.problem(fmt.Errorf("ClusterRole %s aggregation: %w", obj.Metadata.Name, err))
				continue
			}
			for _, candidate := range objects {
				if candidate.Kind == clusterRoleKind && candidate.Metadata.Name != obj.Metadata.Name && matchesAny(selectors, candidate.Metadata.Labels) {
					aggregateSources[obj.Metadata.Name] = append(aggregateSources[obj.Metadata.Name], candidate.Metadata.Name)
					key := roleKey{clusterRoleKind, "", candidate.Metadata.Name}
					if !used[key] {
						used[key] = true
						changed = true
					}
				}
			}
			sort.Strings(aggregateSources[obj.Metadata.Name])
		}
	}
	for _, obj := range objects {
		if (obj.Kind == "Role" || obj.Kind == clusterRoleKind) && used[roleKey{obj.Kind, obj.Metadata.Namespace, obj.Metadata.Name}] {
			role := describe(obj)
			role.AggregateSources = aggregateSources[obj.Metadata.Name]
			report.Roles = append(report.Roles, role)
		}
	}
	for _, def := range roleDefs.Items {
		if !used[roleKey{def.Spec.TargetRole, def.Spec.TargetNamespace, def.Spec.TargetName}] {
			continue
		}
		origin := Origin{Kind: "RoleDefinition", Name: def.Metadata.Name, TargetName: def.Spec.TargetName, TargetRole: def.Spec.TargetRole, Namespace: def.Spec.TargetNamespace}
		if def.Spec.AggregateFrom != nil {
			origin.AggregateSelectors = def.Spec.AggregateFrom.ClusterRoleSelectors
			if _, err := compileSelectors(origin.AggregateSelectors); err != nil {
				report.problem(fmt.Errorf("RoleDefinition %s aggregation: %w", origin.Name, err))
			}
		}
		for _, obj := range objects {
			if (obj.Kind == "Role" || obj.Kind == clusterRoleKind) && ownedBy(obj, "RoleDefinition", origin.Name) {
				generated := describe(obj)
				generated.AggregateSources = aggregateSources[obj.Metadata.Name]
				origin.Generated = append(origin.Generated, generated)
			}
		}
		report.Origins = append(report.Origins, origin)
	}
	sort.SliceStable(report.Origins, func(i, j int) bool {
		return report.Origins[i].Kind+report.Origins[i].Name < report.Origins[j].Kind+report.Origins[j].Name
	})
	return report
}

func subjectMatches(subjects []rbacv1.Subject, username string, groups []string) bool {
	for _, s := range subjects {
		switch s.Kind {
		case "User":
			if s.Name == username {
				return true
			}
		case "Group":
			if slices.Contains(groups, s.Name) {
				return true
			}
		case "ServiceAccount":
			if "system:serviceaccount:"+s.Namespace+":"+s.Name == username {
				return true
			}
		}
	}
	return false
}

func ownedBy(obj observed, kind, name string) bool {
	if obj.Metadata.Annotations[group+"/source-kind"] == kind && obj.Metadata.Annotations[group+"/source-name"] == name {
		return true
	}
	for _, owner := range obj.Metadata.OwnerReferences {
		if owner.APIVersion == group+"/v1alpha1" && owner.Kind == kind && owner.Name == name {
			return true
		}
	}
	return false
}

func describe(obj observed) Generated {
	result := Generated{Kind: obj.Kind, Name: obj.Metadata.Name, Namespace: obj.Metadata.Namespace, RoleRef: obj.RoleRef, Subjects: obj.Subjects}
	if obj.AggregationRule != nil {
		result.AggregateSelectors = obj.AggregationRule.ClusterRoleSelectors
	}
	return result
}

func bindingRefMatches(obj observed, b binding) bool {
	if obj.RoleRef == nil {
		return false
	}
	if b.Namespace != "" && obj.Metadata.Namespace != b.Namespace {
		return false
	}
	return (obj.RoleRef.Kind == "Role" && slices.Contains(b.RoleRefs, obj.RoleRef.Name)) || (obj.RoleRef.Kind == clusterRoleKind && slices.Contains(b.ClusterRoleRefs, obj.RoleRef.Name))
}

func compileSelectors(selectors []metav1.LabelSelector) ([]labels.Selector, error) {
	out := make([]labels.Selector, 0, len(selectors))
	for _, selector := range selectors {
		s, err := metav1.LabelSelectorAsSelector(&selector)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func matchesAny(selectors []labels.Selector, values map[string]string) bool {
	for _, selector := range selectors {
		if selector.Matches(labels.Set(values)) {
			return true
		}
	}
	return false
}

func matchNamespace(report *Report, b binding, kind, query string, namespaces map[string]map[string]string, matches *[]string) *bool {
	if kind == clusterRoleBindingKind {
		yes := true
		return &yes
	}
	var selectors []labels.Selector
	var err error
	if b.Namespace == "" {
		selectors, err = compileSelectors(b.NamespaceSelectors)
	}
	if err != nil {
		report.problem(fmt.Errorf("namespace selector: %w", err))
		return nil
	}
	for name, values := range namespaces {
		if b.Namespace == name || (b.Namespace == "" && matchesAny(selectors, values)) {
			*matches = append(*matches, name)
		}
	}
	sort.Strings(*matches)
	if query == "" {
		no := false
		return &no
	}
	values, found := namespaces[query]
	if !found {
		return nil
	}
	matched := b.Namespace == query || (b.Namespace == "" && matchesAny(selectors, values))
	return &matched
}
