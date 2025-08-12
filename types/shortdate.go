package types

import (
	"fmt"
	"strings"
	"time"
)

const shortDateLayout string = "02/01/2006"

type ShortDate time.Time

func (d *ShortDate) String() string {
	t := time.Time(*d)
	return t.Format(shortDateLayout)
}

func (d ShortDate) MarshalJSON() ([]byte, error) {

	return []byte(fmt.Sprintf(`"%s"`, d.String())), nil
}

func (jt *ShortDate) UnmarshalJSON(b []byte) error {

	timeString := strings.Trim(string(b), `"`)

	t, err := time.Parse(shortDateLayout, timeString)
	if err == nil {
		*jt = ShortDate(t)
		return nil
	}

	return fmt.Errorf("invalid date format: %s", timeString)
}

func (d *ShortDate) ToTime() *time.Time {
	var result time.Time
	if d != nil {
		result = time.Time(*d)
		return &result
	}

	return nil
}
