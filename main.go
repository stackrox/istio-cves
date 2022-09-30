package main

import (
	validation2 "github.com/stackrox/istio-cves/validation"
	"log"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
)

const (
	vulnsPath = "vulns"
)

func main() {
	err := filepath.Walk(vulnsPath, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if path == vulnsPath {
			return nil
		}

		if filepath.Ext(path) != ".yaml" {
			return errors.Errorf("CVE file must have .yaml extension: %s", path)
		}

		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var vuln validation2.Vuln
		if err := yaml.Unmarshal(bytes, &vuln); err != nil {
			return errors.Wrapf(err, "unable to unmarshal %s", path)
		}

		if err := validation2.Validate(path, &vuln); err != nil {
			return errors.Wrapf(err, "CVE file %s is invalid", path)
		}

		return nil
	})

	if err != nil {
		log.Fatalf("Error validating CVEs: %v", err)
	}
}
