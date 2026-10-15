/*
Copyright 2020 Cornelius Weig

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"flag"
	"fmt"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	rakkess "github.com/corneliusweig/rakkess/internal"
	"github.com/corneliusweig/rakkess/internal/authoperator"
	"github.com/corneliusweig/rakkess/internal/constants"
	"github.com/corneliusweig/rakkess/internal/diff"
	"github.com/corneliusweig/rakkess/internal/options"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

var (
	opts            = options.NewRakkessOptions()
	diffWith        []string
	authOperator    bool
	baseImpersonate string
)

const (
	rakkessLongDescription = `
Show an access matrix for all server resources

This command slices the authorization space (subject, resource, verb)
along a plane of fixed subject.

Rakkess retrieves the full list of server resources, checks access for
the current user with the given verbs, and prints the result as a matrix.
This complements the usual "kubectl auth can-i" command, which works for
a single resource and a single verb.

When passing the --diff-with flag, the matrix shows only the diff of the access
rights. The diff-with flag takes overrides in the form "flag=value". It accepts
the same flags as rakkess itself (without the leading --). The flag can be
repeated.
For example: --diff-with context=b --diff-with sa=kube-system:job-controller

More on https://github.com/corneliusweig/rakkess/blob/v0.5.0/doc/USAGE.md#usage
`

	rakkessExamples = `
  Review access to cluster-scoped resources
   $ rakkess

  Review access to namespaced resources in 'default'
   $ rakkess --namespace default

  Review access as a different user
   $ rakkess --as other-user

  Review access as a service-account
   $ rakkess --sa kube-system:namespace-controller

  Review access for different verbs
   $ rakkess --verbs get,watch,patch

  Review access rights diff with another service account
   $ rakkess --diff-with sa=kube-system:namespace-controller
`
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     constants.CommandName,
	Short:   "Review access - show an access matrix for all resources",
	Long:    constants.HelpTextMapName(rakkessLongDescription),
	Example: constants.HelpTextMapName(rakkessExamples),
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGPIPE, syscall.SIGTERM)
		defer stop()

		res, err := rakkess.Resource(ctx, opts)
		if err != nil {
			return err
		}
		var provenance map[string]authoperator.Report
		if authOperator {
			provenance = map[string]authoperator.Report{"original": collectAuthOperator(ctx)}
		}
		if diffWith == nil {
			t := res.Table(opts.Verbs)
			t.Render(opts.Streams.Out, opts.OutputFormat)
			return writeAuthOperator(provenance)
		}

		orig := res
		originalVerbs := slices.Clone(opts.Verbs)
		if opts.ConfigFlags.Impersonate != nil {
			*opts.ConfigFlags.Impersonate = baseImpersonate
		}
		flags := cmd.Flags()
		resetSlices := map[string]bool{}

		for _, arg := range diffWith {
			name, value, ok := strings.Cut(arg, "=")
			if !ok {
				return fmt.Errorf("diffWith expects format flag=value, got %s", arg)
			}
			fl := flags.Lookup(name)
			if fl == nil && len(name) == 1 {
				fl = flags.ShorthandLookup(name)
			}
			if fl == nil {
				return fmt.Errorf("flag %q does not exist", name)
			}
			klog.V(2).Infof("Override flag %s=%s", name, value)
			// Overrides replace repeated values such as --as-group rather than
			// retaining the original identity's groups in the comparison.
			if slice, ok := fl.Value.(pflag.SliceValue); ok && !resetSlices[fl.Name] {
				if err := slice.Replace(nil); err != nil {
					return fmt.Errorf("reset %s: %w", name, err)
				}
				resetSlices[fl.Name] = true
			}
			if err := fl.Value.Set(value); err != nil {
				return fmt.Errorf("failed to set %s=%s", name, value)
			}
		}
		if err := opts.ExpandServiceAccount(); err != nil { // expand again in case `--sa` was overridden
			return err
		}
		opts.ExpandVerbs()
		mod, err := rakkess.Resource(ctx, opts)
		if err != nil {
			return fmt.Errorf("with modified flags: %w", err)
		}

		verbs := originalVerbs
		for _, verb := range opts.Verbs {
			if !slices.Contains(verbs, verb) {
				verbs = append(verbs, verb)
			}
		}
		t := diff.Diff(orig, mod, verbs)
		t.Render(opts.Streams.Out, opts.OutputFormat)
		if provenance != nil {
			provenance["modified"] = collectAuthOperator(ctx)
		}
		return writeAuthOperator(provenance)
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		if n := opts.ConfigFlags.Namespace; n == nil || *n == "" {
			fmt.Fprintf(opts.Streams.Out, "No namespace given, this implies cluster scope (try -n if this is not intended)\n")
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	rootCmd.SetOut(opts.Streams.Out)
	rootCmd.SetErr(opts.Streams.ErrOut)
	return rootCmd.Execute()
}

func init() {
	klog.InitFlags(flag.CommandLine)
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)

	AddRakkessFlags(rootCmd)
	rootCmd.Flags().BoolVar(&authOperator, "auth-operator", false, "include advisory auth-operator definitions and observed RBAC provenance as JSON on stderr")
	rootCmd.Flags().StringVar(&opts.AsServiceAccount, constants.FlagServiceAccount, "", "similar to --as, but impersonate as service-account. The argument must be qualified <namespace>:<sa-name> or be combined with the --namespace option. Takes precedence over --as.")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		opts.ExpandVerbs()
	}
	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		baseImpersonate = ""
		if opts.ConfigFlags.Impersonate != nil {
			baseImpersonate = *opts.ConfigFlags.Impersonate
		}
		return opts.ExpandServiceAccount()
	}
}

// AddRakkessFlags sets up common flags for subcommands.
func AddRakkessFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&opts.Verbs, constants.FlagVerbs, []string{"list", "create", "update", "delete"}, fmt.Sprintf("show access for verbs out of (%s)", strings.Join(constants.ValidVerbs, ", ")))
	cmd.Flags().StringVarP(&opts.OutputFormat, constants.FlagOutput, "o", "icon-table", fmt.Sprintf("output format out of (%s)", strings.Join(constants.ValidOutputFormats, ", ")))
	cmd.Flags().StringSliceVar(&diffWith, constants.FlagDiffWith, nil, "Show diff for modified call. For example --diff-with=namespace=kube-system.")

	opts.ConfigFlags.AddFlags(cmd.Flags())
}
