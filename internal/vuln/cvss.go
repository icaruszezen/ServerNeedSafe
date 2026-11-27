package vuln

import (
	"math"
	"strconv"
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// ParseCVSSScoreAndSeverity parses either a numeric score string ("9.8") or a CVSS v3.0 / v3.1 vector string
// ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") into a numeric base score and canonical VulnSeverity.
func ParseCVSSScoreAndSeverity(raw string) (float64, vault.VulnSeverity) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, vault.VulnSeverityUnknown
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 && f <= 10.0 {
		score := math.Round(f*10) / 10
		return score, vault.SeverityFromCVSS(score)
	}
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "CVSS:3.0/") || strings.HasPrefix(upper, "CVSS:3.1/") {
		if score, ok := calcCVSSv3BaseScore(upper); ok {
			return score, vault.SeverityFromCVSS(score)
		}
	}
	return 0, vault.VulnSeverityUnknown
}

// calcCVSSv3BaseScore implements the official FIRST CVSS v3.0/v3.1 Base Score specification.
func calcCVSSv3BaseScore(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	metrics := make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if ok {
			metrics[k] = v
		}
	}

	avMap := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acMap := map[string]float64{"L": 0.77, "H": 0.44}
	uiMap := map[string]float64{"N": 0.85, "R": 0.62}
	ciaMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

	av, okAV := avMap[metrics["AV"]]
	ac, okAC := acMap[metrics["AC"]]
	ui, okUI := uiMap[metrics["UI"]]
	c, okC := ciaMap[metrics["C"]]
	i, okI := ciaMap[metrics["I"]]
	a, okA := ciaMap[metrics["A"]]
	scope := metrics["S"]
	if !okAV || !okAC || !okUI || !okC || !okI || !okA || (scope != "U" && scope != "C") {
		return 0, false
	}

	var pr float64
	switch metrics["PR"] {
	case "N":
		pr = 0.85
	case "L":
		if scope == "C" {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scope == "C" {
			pr = 0.50
		} else {
			pr = 0.27
		}
	default:
		return 0, false
	}

	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0.0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	var raw float64
	if scope == "U" {
		raw = math.Min(impact+exploitability, 10.0)
	} else {
		raw = math.Min(1.08*(impact+exploitability), 10.0)
	}
	return cvssRoundUp1(raw), true
}

func cvssRoundUp1(val float64) float64 {
	intInput := math.Round(val * 100000)
	if int64(intInput)%10000 == 0 {
		return intInput / 100000.0
	}
	return (math.Floor(intInput/10000.0) + 1.0) / 10.0
}
