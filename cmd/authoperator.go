package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/corneliusweig/rakkess/internal/authoperator"
)

func collectAuthOperator(ctx context.Context) authoperator.Report {
	cfg, err := opts.ConfigFlags.ToRESTConfig()
	if err != nil {
		return authoperator.Report{Advisory: true, Errors: []string{err.Error()}}
	}
	namespace := ""
	if opts.ConfigFlags.Namespace != nil {
		namespace = *opts.ConfigFlags.Namespace
	}
	report := authoperator.Collect(ctx, cfg, namespace)
	if opts.DiscoveryError != nil {
		report.Complete = false
		report.Errors = append(report.Errors, fmt.Sprintf("resource discovery incomplete: %v", opts.DiscoveryError))
	}
	return report
}

func writeAuthOperator(reports map[string]authoperator.Report) error {
	if reports == nil {
		return nil
	}
	// Keep the effective-access table on stdout; provenance is advisory metadata.
	return json.NewEncoder(opts.Streams.ErrOut).Encode(map[string]map[string]authoperator.Report{"authOperator": reports})
}
