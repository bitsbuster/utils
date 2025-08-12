package database

import "database/sql"

type EnhacedTx struct {
	tx   *sql.Tx
	open bool
}

// Query executes a query that returns rows, typically a SELECT.
func (v *EnhacedTx) Query(query string, args ...any) (*sql.Rows, error) {
	return v.tx.Query(query, args...)
}

// QueryRow executes a query that is expected to return at most one row.
// QueryRow always returns a non-nil value. Errors are deferred until
// [Row]'s Scan method is called.
func (v *EnhacedTx) QueryRow(query string, args ...any) *sql.Row {
	return v.tx.QueryRow(query, args...)
}

// Exec executes a query that doesn't return rows.
// For example: an INSERT and UPDATE.
func (v *EnhacedTx) Exec(query string, args ...any) (sql.Result, error) {
	return v.tx.Exec(query, args...)
}

// Commit commits the transaction
func (v *EnhacedTx) Commit() error {
	var err error
	if v.open {
		err = v.tx.Commit()
		v.open = false
	}
	return err
}

// Rollback aborts the transaction
func (v *EnhacedTx) Rollback() error {
	var err error
	if v.open {
		err = v.tx.Rollback()
		v.open = false
	}
	return err
}

// IsOpen returns true if the transaction is still active
func (v *EnhacedTx) IsActive() bool {
	return v.open
}

// ForceClose closes and aborts the transaction
func (v *EnhacedTx) ForceClose() error {
	return v.Rollback()
}
