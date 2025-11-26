package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bitsbuster/utils/v2/errors"
	"github.com/bitsbuster/utils/v2/log"

	_ "github.com/go-sql-driver/mysql" // register mysql
	_ "github.com/lib/pq"              // register postgres
)

const (
	DEFAULT_TIMEOUT_SECONDS   int           = 5
	DEFAULT_MAX_OPEN_CONNS    int           = 10
	DEFAULT_MAX_IDLE_CONNS    int           = 10
	DEFAULT_CONN_MAX_LIFETIME time.Duration = 5 * time.Minute
)

type DbDriver string

const (
	DB_DRIVER_MYSQL    DbDriver = "mysql"
	DB_DRIVER_POSTGRES DbDriver = "postgres"
)

type DbPool struct {
	pool *sql.DB
}

type Connection interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// DbConfig is the generic configuration for all SQL engines.
type DbConfig struct {
	Driver DbDriver
	User   string
	Pass   string
	Host   string
	Port   int
	DBName string

	TimeoutSeconds  int // connection timeout
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// CreateDbPool creates a connection pool for the given database configuration.
//
// The given database configuration is used to create a connection pool.
// The connection pool is created with the following settings:
// - Max open connections: cfg.MaxOpenConns (default: 10)
// - Max idle connections: cfg.MaxIdleConns (default: 10)
// - Connection max lifetime: cfg.ConnMaxLifetime (default: 5 minutes)
// - Connection timeout: cfg.TimeoutSeconds (default: 5 seconds)
//
// The connection pool is created by calling sql.Open() with the
// database configuration.
//
// If the connection pool cannot be created, an error is returned.
//
// The returned error is of type *errors.CommonsError and contains the
// error code "ERROR_OPENING_DATABASE" and the error message returned by
// sql.Open().
func CreateDbPool(cfg DbConfig) (*DbPool, error) {

	log.Infof(nil, "Creating connection pool for %s:%s@tcp(%s:%d)/%s (timeout=%ds)",
		cfg.Driver, cfg.User, cfg.Host, cfg.Port, cfg.DBName, cfg.TimeoutSeconds)

	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = DEFAULT_TIMEOUT_SECONDS
		log.Infof(nil, "Setting timeout to default value of %d seconds", DEFAULT_TIMEOUT_SECONDS)
	}

	dsn, err := buildDSN(cfg)
	if err != nil {
		log.Errorf(nil, "Failed to build DSN: %+v", err)
		return nil, err
	}

	log.Infof(nil, "Using DSN: %s", dsn)

	db, err := sql.Open(string(cfg.Driver), dsn)
	if err != nil {
		log.Errorf(nil, "Failed opening database: %+v", err)
		return nil, errors.New("ERROR_OPENING_DATABASE", err.Error())
	}

	log.Infof(nil, "Opened database connection pool")

	// Pool settings
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
		log.Infof(nil, "Setting max open connections to %d", cfg.MaxOpenConns)
	} else {
		db.SetMaxOpenConns(DEFAULT_MAX_OPEN_CONNS)
		log.Infof(nil, "Setting max open connections to default value of %d", DEFAULT_MAX_OPEN_CONNS)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
		log.Infof(nil, "Setting max idle connections to %d", cfg.MaxIdleConns)
	} else {
		db.SetMaxIdleConns(DEFAULT_MAX_IDLE_CONNS)
		log.Infof(nil, "Setting max idle connections to default value of %d", DEFAULT_MAX_IDLE_CONNS)
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
		log.Infof(nil, "Setting connection max lifetime to %v", cfg.ConnMaxLifetime)
	} else {
		db.SetConnMaxLifetime(DEFAULT_CONN_MAX_LIFETIME)
		log.Infof(nil, "Setting connection max lifetime to default value of %v", DEFAULT_CONN_MAX_LIFETIME)
	}

	// Health check with timeout
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Errorf(nil, "Database unreachable: %+v", err)
		return nil, errors.New("ERROR_DATABASE_UNREACHABLE", err.Error())
	}

	return &DbPool{pool: db}, nil
}

// ----------------------------------------------------------------------
// DSN BUILDERS
// ----------------------------------------------------------------------

func buildDSN(cfg DbConfig) (string, error) {

	switch cfg.Driver {
	case DB_DRIVER_MYSQL:
		return fmt.Sprintf(
			"%s:%s@tcp(%s:%d)/%s?parseTime=true&timeout=%ds",
			cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.DBName, cfg.TimeoutSeconds,
		), nil

	case DB_DRIVER_POSTGRES:
		// SSL disabled by default;
		// refer to https://www.postgresql.org/docs/9.1/libpq-ssl.html
		return fmt.Sprintf(
			"postgres://%s:%s@%s:%d/%s?sslmode=disable&connect_timeout=%d",
			cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.DBName, cfg.TimeoutSeconds,
		), nil
	}

	return "", errors.New("ERROR_UNSUPPORTED_DRIVER", fmt.Sprintf("Driver %s is not supported", cfg.Driver))
}

// ----------------------------------------------------------------------
// Public pool methods
// ----------------------------------------------------------------------

func (d *DbPool) GetConnection() *sql.DB {
	return d.pool
}

func (d *DbPool) Close() {
	if d.pool != nil {
		_ = d.pool.Close()
	}
}

// ----------------------------------------------------------------------
// Transactions (enhanced + context support)
// ----------------------------------------------------------------------

func (d *DbPool) BeginTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := d.pool.BeginTx(ctx, nil)
	if err != nil {
		log.Errorf(nil, "Error beginning transaction: %+v", err)
		return nil, errors.New("ERROR_BEGINNING_TRANSACTION", err.Error())
	}
	return tx, nil
}

func (d *DbPool) BeginEnhacedTx(ctx context.Context) (*EnhacedTx, error) {
	tx, err := d.pool.BeginTx(ctx, nil)
	if err != nil {
		log.Errorf(nil, "Error beginning enhanced transaction: %+v", err)
		return nil, errors.New("ERROR_BEGINNING_TRANSACTION", err.Error())
	}
	return &EnhacedTx{tx: tx, open: true}, nil
}

// ----------------------------------------------------------------------
// SQL Error Normalizer (MySQL or generic)
// ----------------------------------------------------------------------

func GetSqlError(err error) error {
	if err == nil {
		return nil
	}

	// Handle "no rows"
	if err == sql.ErrNoRows {
		return errors.NewErrorEmptySqlResult("Empty sql result")
	}

	// Try MySQL error (only if MySQL driver used)
	type mysqlErr interface{ Number() uint16 }
	if me, ok := err.(mysqlErr); ok {
		if me.Number() == 1062 {
			return errors.NewErrorDatabaseDuplicated("Duplicated entity")
		}
	}

	return errors.New("ERROR_DATABASE", err.Error())
}
