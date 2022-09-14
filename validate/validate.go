package main

import (
	"github.com/pkg/errors"
	"github.com/stackrox/istio-cves"
	"regexp"
	"strings"
	"time"
)

const (
	linkFmt = "https://istio.io/latest/news/security/istio-security-%d-%d"
)

var (
	firstPublishedCVE time.Time

	vulnPattern = regexp.MustCompile(`^ISTIO-SECURITY-(\d{4})-(\d{3})$`)
)

func init() {
	var err error
	firstPublishedCVE, err = time.Parse(istio.TimeLayout, "2019-05-28T00:00Z")
	if err != nil {
		panic("Should not happen")
	}
}

func validate(fileName string, vuln *istio.Vuln) error {
	// Validate vuln name.
	if !vulnPattern.MatchString(vuln.Name) {
		return errors.Errorf("Vuln name must adhere to the pattern %q: %s", vulnPattern.String(), vuln.Name)
	}

	// Validate file name.
	if !strings.HasSuffix(fileName, cveFile.CVE+".yaml") {
		return errors.Errorf("file name must match CVE (%q)", cveFile.CVE)
	}
}
