package validation

import (
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

const TimeLayout = schema.TimeLayout

type Vuln struct {
	Name        string     `json:"name"`
	Link        string     `json:"link"`
	Published   Time       `json:"published"`
	Description string     `json:"description"`
	CVSS        CVSS       `json:"cvss"`
	Affected    []Affected `json:"affected"`
}

type CVSS struct {
	ScoreV3  float64 `json:"scoreV3"`
	VectorV3 string  `json:"vectorV3"`
}

type Affected struct {
	Range   string `json:"range"`
	FixedBy string `json:"fixedBy"`
}

// Time is a wrapper around time.Time.
// The default UnmarshalJSON for time.Time expects the time.RFC3339 format,
// which is not what is used in this repo.
type Time struct {
	time.Time
}

// UnmarshalJSON is inspired by the Go 1.18 (*time.Time).UnmarshalJSON implementation
// https://cs.opensource.google/go/go/+/refs/tags/go1.18:src/time/time.go;l=1298.
func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var err error
	t.Time, err = time.Parse(`"`+TimeLayout+`"`, string(data))
	return err
}
