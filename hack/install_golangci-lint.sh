#!/bin/sh
set -eu

bindir=./bin
while getopts 'b:' opt; do
  case "$opt" in
    b) bindir=$OPTARG ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))
version=${1:-v2.14.0}

mkdir -p "$bindir"
GOBIN=$(cd "$bindir" && pwd) go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$version"
