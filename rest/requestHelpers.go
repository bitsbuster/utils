package rest

import (
	"io"
	"net/http"
	"strconv"

	"github.com/bitsbuster/utils/v2/decoder"
	"github.com/bitsbuster/utils/v2/errors"
	"github.com/bitsbuster/utils/v2/log"
)

type FilterParamsDTO struct {
	StartDate int64
	EndDate   int64
	Offset    uint32
	MaxRows   uint32
}

const (
	PARAM_OFFSET           string = "offset"
	PARAM_MAX_ROWS         string = "limit"
	QUERY_PARAM_START_DATE string = "startDate"
	QUERY_PARAM_END_DATE   string = "endDate"
)

func DecodeRequestIntoStruct(w http.ResponseWriter, r *http.Request, dest interface{}) error {

	body2, err := io.ReadAll(r.Body)

	if err != nil {
		log.Errorf(nil, "Error with received json, seems to be invalid: no extra inf. %+v", err)
		ReturnRawError(w, "INVALID_DATA", "Review sent data", http.StatusForbidden)
		return err
	}
	defer r.Body.Close()

	err = decoder.JsonNumberDecode(body2, &dest)

	if err != nil {
		log.Errorf(nil, "Error with received json, cannot be decoded into NewWalletUserDTO. %+v", err)
		ReturnRawError(w, "JSON_ERROR", err.Error(), http.StatusBadRequest)
		return err
	}
	return nil
}

// parseRequestFilterParams parses the request filter parameters and fills the FilterParamsDTO struct.
// The function logs any errors found in the parameters and fills the struct with default values.
// If the FilterParamsDTO parameter is nil, a new one is created.
func ParseRequestFilterParams(r *http.Request, f *FilterParamsDTO) {

	var err error

	ctx := r.Context()

	if f == nil {
		f = &FilterParamsDTO{}
	}

	f.Offset, f.MaxRows, err = GetPaginationValues(r)

	if err != nil {
		log.Traceln(&ctx, "Invalid pagination params received, using default values:")

	}

	startDateStr := r.URL.Query().Get(QUERY_PARAM_START_DATE)

	f.StartDate, err = strconv.ParseInt(startDateStr, 10, 64)
	if err != nil {
		log.Errorf(&ctx, "Invalid start date value {%s}: %+v", startDateStr, err)
	}

	endDateStr := r.URL.Query().Get(QUERY_PARAM_END_DATE)

	f.EndDate, err = strconv.ParseInt(endDateStr, 10, 64)
	if err != nil {
		log.Errorf(&ctx, "Invalid end date value {%s}: %+v", startDateStr, err)
	}

}

// GetPaginationValues extracts pagination parameters from the request URL.
// It parses 'offset' and 'maxRows' query parameters into uint32 values.
// Returns the parsed values and an error if any of the parameters are invalid.
func GetPaginationValues(r *http.Request) (uint32, uint32, error) {
	offsetStr := r.URL.Query().Get(PARAM_OFFSET)
	maxRowsStr := r.URL.Query().Get(PARAM_MAX_ROWS)

	var offset, maxRows uint64
	var err error

	if offsetStr != "" {
		offset, err = strconv.ParseUint(offsetStr, 10, 64)
		if err != nil {
			return 0, 0, errors.New("PAGINATION_ERROR_OFFSET", "Invalid offset value")
		}
	}

	if offset < 1 {
		offset = 1
	}
	if maxRowsStr != "" {
		maxRows, err = strconv.ParseUint(maxRowsStr, 10, 64)
		if err != nil {
			return 0, 0, errors.New("PAGINATION_ERROR_LIMIT", "Invalid limit value")
		}
	}

	if maxRows < 1 {
		maxRows = 25
	}
	if maxRows > 100 {
		maxRows = 100
	}
	return uint32(offset - 1), uint32(maxRows), nil
}
