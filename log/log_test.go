package log_test

import (
	"os"
	"testing"

	"github.com/bitsbuster/utils/log"
)

func TestDebug(t *testing.T) {
	kk := "All is fine"
	log.LogLevel = log.TRACE
	log.SetOutput(os.Stdout)
	log.Debugln(nil, "Information message: %s", kk)
	log.Debugln(nil, "Debug ln")
}
