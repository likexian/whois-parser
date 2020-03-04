package whoisparser

import (
	"strings"
	"time"
)

func parseDate(extension, d string) (time.Time, error) {
	if len(d) == 0 {
		return time.Time{}, nil
	}

	d = fixDateInput(extension, d)

	// first try long time, then short

	layout := getLongDateFormat(extension)

	t, err := time.Parse(layout, d)
	if err != nil {
		if _, ok := err.(*time.ParseError); ok {

			// try short format
			layout = getShortDateFormat(extension)

			t, err = time.Parse(layout, d)
			if err != nil {
				return time.Time{}, err
			}
		} else {
			return time.Time{}, err
		}
	}

	return t, nil
}

func getLongDateFormat(extension string) string {
	switch extension {
	case "cat":
		return "2006-01-02T15:04:05.999Z"

	case "cn":
		return "2006-01-02 15:04:05"

	case "fi":
		return "2.1.2006 15:04:05"

	case "jp":
		return "2006/01/02 15:04:05 (MST)"

	case "mo", "it":
		return "2006-01-02 15:04:05"

	case "tw":
		return "2006-01-02 (YYYY-MM-DD)"

	case "xyz":
		return "2006-01-02T15:04:05.0Z"

	default:
		return time.RFC3339
	}
}

func getShortDateFormat(extension string) string {
	switch extension {
	case "fi":
		return "2.1.2006"

	case "hk":
		return "02-01-2006"

	case "br":
		return "20060102"

	case "kr":
		return "2006. 01. 02."

	case "edu":
		return "02-Jan-2006"

	case "ch":
		return "02 Jan 2006"

	case "jp":
		return "2006/01/02"

	case "tk":
		return "01/02/2006"

	case "uk":
		return "02-Jan-2006"

	default:
		return "2006-01-02"
	}
}

func fixDateInput(extension, d string) string {
	switch extension {
	case "br":
		parts := strings.Split(d, "#")
		return strings.TrimSpace(parts[0])

	default:
		return d
	}
}
