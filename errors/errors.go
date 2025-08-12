package errors

const (
	ErrorNilEntityValue     = "ERROR_NIL_ENTITY_VALUE"
	ErrorEmptySqlResult     = "ERROR_EMPTY_SQL_RESULT"
	ErrorDatabaseDuplicated = "ERROR_DUPLICATED_ENTRY"
	ErrorNoRowsAffected     = "ERROR_SQL_NO_ROWS_AFFECTED"
	ErrorGeneratingRsa      = "ERROR_GENERATING_RSA"
)

func NewErrorNilEntityValue(text string) error {
	return &CommonsError{ErrorNilEntityValue, text}
}

func NewErrorEmptySqlResult(text string) error {
	return &CommonsError{ErrorEmptySqlResult, text}
}

func NewErrorDatabaseDuplicated(text string) error {
	return &CommonsError{ErrorDatabaseDuplicated, text}
}

func NewErrorNoRowsAffected(text string) error {
	return &CommonsError{ErrorNoRowsAffected, text}
}
