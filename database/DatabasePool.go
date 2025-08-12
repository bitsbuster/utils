package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/bitsbuster/utils/errors"
	"github.com/bitsbuster/utils/log"
	"github.com/go-sql-driver/mysql"
)

type DbPool struct {
	pool *sql.DB
}

type Connection interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// CreateDbPool creates the DB connections pool. time out must be in seconds
func CreateDbPool(user, password, databaseName, host string, port, timeout uint16) (*DbPool, error) {
	var err error

	result := DbPool{}
	dbURI := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&timeout=%ds", user, password, host, port, databaseName, timeout)

	log.Infof(nil, "Creating connection to %s:*******@tcp(%s:%d)/%s?parseTime=true&timeout=%ds", user, host, port, databaseName, timeout)

	result.pool, err = sql.Open("mysql", dbURI)
	if err != nil {
		log.Errorf(nil, "Failed openning database at {%s}: %+v", dbURI, err)
		return nil, errors.New("ERROR_OPENING_DATABASE", fmt.Sprintf("Failed openning database at {%s}: %+v", dbURI, err))
	}

	if err = result.pool.Ping(); err != nil {
		log.Errorf(nil, "Cannot stablish connection with database: %+v", err)
		return nil, errors.New("ERROR_DATABASE_UNREACHABLE", "Cannot stablish connection with database")
	}

	return &result, nil

}

// Gets the DB connection
func (d *DbPool) GetConnection() *sql.DB {
	return d.pool
}

// Close closes de DB connection
func (d *DbPool) Close() {
	if d.pool != nil {
		d.pool.Close()
	}
}

// Returns a new Transaction
func (d *DbPool) BeginTx() (*sql.Tx, error) {

	tx, err := d.pool.BeginTx(context.Background(), nil)
	if err != nil {
		log.Errorf(nil, "Error begining transaction: %+v", err)
		return nil, errors.New("ERROR_BEGINING_TRANSACTION", fmt.Sprintf("Error begining transaction: %+v", err))
	}

	return tx, nil

}

// Returns a new Enhaced Improved Transaction
func (d *DbPool) BeginEnhacedTx() (*EnhacedTx, error) {
	tx, err := d.pool.BeginTx(context.Background(), nil)
	if err != nil {
		log.Errorf(nil, "Error begining Enhaced transaction: %+v", err)
		return nil, errors.New("ERROR_BEGINING_TRANSACTION", fmt.Sprintf("Error begining Enhaced transaction: %+v", err))
	}

	return &EnhacedTx{tx: tx, open: true}, nil

}

func GetSqlError(err error) error {
	if err == nil {
		return nil
	}

	merror, ok := err.(*mysql.MySQLError)
	if !ok {
		if err.Error() == "sql: no rows in result set" {

			return errors.NewErrorEmptySqlResult("Empty sql result")
		}
		return errors.New("ERROR_DATABASE", err.Error())
	}

	if merror.Number == 1062 {
		return errors.NewErrorDatabaseDuplicated("Duplicated entity")
	}

	return err

}
