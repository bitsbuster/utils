package database

import (
	"database/sql"

	"github.com/bitsbuster/utils/errors"
	"github.com/bitsbuster/utils/log"
)

// Manages the possible error coming for an update execution and returns the database error if exists.
// If not, it checks if any row has been affected and returns err if nothing has been updated.
//
//	  params
//
//		'callerName' is the name of the caller function, it is used in log message
//		'result' is the sql.Result returned by Exec function
//		'err' is the error returned by Exec function
func ManageUpdateError(callerName string, result sql.Result, err error) error {
	if err != nil {
		serr := GetSqlError(err)
		log.Errorf(nil, "%s: Error persisting information at DB. %+v", callerName, serr)
		return serr
	}

	if kk, _ := result.RowsAffected(); kk == 0 {
		log.Errorf(nil, "%s: Nothing updated at database.", callerName)
		return errors.NewErrorNoRowsAffected("Nothing updated at database")
	}

	return nil
}
