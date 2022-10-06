package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/facebookincubator/nvdtools/cvss3"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/stackrox/istio-cves/types"
)

const (
	linkFmt = "https://istio.io/latest/news/security/%s/"
)

var (
	firstPublishedCVE = time.Time{}

	vulnPattern = regexp.MustCompile(`^ISTIO-SECURITY-(\d{4})-(\d{3})$`)
)

func init() {
	var err error
	firstPublishedCVE, err = time.Parse(types.TimeLayout, "2019-05-28T00:00Z")
	if err != nil {
		panic("Should not happen")
	}
}

// validate yaml files
func validate(fileName string, vuln *types.Vuln) error {
	// validate vuln name.
	if !vulnPattern.MatchString(vuln.Name) {
		return errors.Errorf("Vuln name must adhere to the pattern %q: %s", vulnPattern.String(), vuln.Name)
	}

	// validate file name.
	if !strings.HasSuffix(fileName, vuln.Name+".yaml") {
		return errors.Errorf("file name must match CVE (%q)", vuln.Name)
	}

	// validate link format
	if vuln.Link != fmt.Sprintf(linkFmt, strings.ToLower(vuln.Name)) {
		return errors.Errorf("Vuln link must include vlun name %s: %s", vuln.Link, vuln.Name)
	}

	// validate published.
	if vuln.Published.Before(firstPublishedCVE) {
		return errors.Errorf("published time must be before %s", firstPublishedCVE.String())
	}

	// validate description.
	if len(strings.TrimSpace(vuln.Description)) == 0 {
		return errors.New("description must be defined")
	}

	// validate CVSS.
	if err := validateCVSS(vuln.CVSS); err != nil {
		return errors.Wrap(err, "invalid CVSS field")
	}

	// validate affected.
	if err := validateAffected(vuln.Affected); err != nil {
		return errors.Wrap(err, "invalid affected field")
	}

	return nil
}

func validateCVSS(cvss types.CVSS) error {
	if cvss.ScoreV3 <= 0.0 {
		return errors.New("scoreV3 must be defined and greater than 0.0")
	}

	if err := validateCVSSv3(cvss.ScoreV3, cvss.VectorV3); err != nil {
		return errors.Wrap(err, "invalid CVSS3")
	}

	return nil
}

func validateCVSSv3(score float64, vector string) error {
	v, err := cvss3.VectorFromString(vector)
	if err != nil {
		return err
	}
	if err := v.Validate(); err != nil {
		return err
	}

	calculatedScore := v.BaseScore()
	if score != calculatedScore {
		return errors.Errorf("CVSS3 score differs from calculated vector score: %f != %0.1f", score, calculatedScore)
	}

	return nil
}

func validateAffected(affects []types.Affected) error {
	if len(affects) == 0 {
		return errors.New("affected must be defined")
	}

	affectedSet := make(map[string]bool)
	for _, affected := range affects {
		trimmedRange := strings.TrimSpace(affected.Range)
		if len(trimmedRange) == 0 {
			return errors.New("affected range must not be blank")
		}
		if affectedSet[trimmedRange] {
			return errors.Errorf("affected range must not be repeated: %s", trimmedRange)
		}
		affectedSet[trimmedRange] = true

		// It would be nice if we could ensure all ranges are non-overlapping,
		// but it doesn't seem very straightforward at the moment.
		c, err := version.NewConstraint(trimmedRange)
		if err != nil {
			return errors.Wrapf(err, "invalid affected range: %s", trimmedRange)
		}

		trimmedFixedBy := strings.TrimSpace(affected.FixedBy)
		if len(trimmedFixedBy) == 0 {
			// fixedBy need not be defined.
			continue
		}
		v, err := version.NewVersion(trimmedFixedBy)
		if err != nil {
			return errors.Wrapf(err, "invalid fixedBy: %s", trimmedFixedBy)
		}

		// It would be nice if we could ensure the version is above the range,
		// but it doesn't seem very straightforward at the moment.
		if c.Check(v) {
			return errors.Errorf("fixedBy must not be within the given range: %s contains %s", trimmedRange, trimmedFixedBy)
		}
	}

	return nil
}
