package db

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const MaxTaskCVECount = 100

var (
	ErrCVEInvalid = errors.New("invalid CVE id")
	cveIDPattern  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

func NormalizeCVEID(raw string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))
	if !cveIDPattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: %q must match CVE-YYYY-NNNN", ErrCVEInvalid, raw)
	}
	return normalized, nil
}

func NormalizeCVEIDs(ids []string) ([]string, error) {
	normalized := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, raw := range ids {
		id, err := NormalizeCVEID(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
		if len(normalized) > MaxTaskCVECount {
			return nil, fmt.Errorf("%w: at most %d unique CVE ids per task", ErrCVEInvalid, MaxTaskCVECount)
		}
	}
	return normalized, nil
}
