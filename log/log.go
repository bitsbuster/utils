package log

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/bitsbuster/utils/v2/contextkeys"
	"github.com/bitsbuster/utils/v2/types"
)

type LogFormat uint8

const (
	RAW LogFormat = iota
	JSON
)

var format LogFormat = RAW

type LogLevelValue uint8

const (
	TRACE LogLevelValue = iota
	DEBUG
	INFO
	WARN
	ERROR
	FATAL
)

var levelNames []string = []string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"}

type LogEntry struct {
	Timestamp  string  `json:"timestamp"`
	Level      string  `json:"level"`
	RequestID  string  `json:"request_id,omitempty"`
	Caller     string  `json:"caller,omitempty"`
	User       string  `json:"user,omitempty"`
	Method     string  `json:"method,omitempty"`
	Path       string  `json:"path,omitempty"`
	Status     int     `json:"status,omitempty"`
	IP         string  `json:"ip,omitempty"`
	DurationMS float64 `json:"duration_ms,omitempty"`
	App        string  `json:"app,omitempty"`
	Env        string  `json:"env,omitempty"`
	Message    string  `json:"message"`
}

var Environment string

func init() {
	SetFlags(LstdFlags | Lmicroseconds)
}

// SetFormat changes the log format to the given format.
//
// If the format is JSON, the logger will not include the date and time
// in the log entry. If the format is RAW, the logger will include the
// date and time in the log entry.
func SetFormat(f LogFormat) {
	if f == JSON {
		SetFlags(LstdFlags &^ (Ldate | Ltime))
		format = f
	} else {
		SetFlags(LstdFlags | Lmicroseconds)
		format = RAW
	}
}

func (p *LogLevelValue) FromString(s string) {
	for i, v := range levelNames {
		if strings.EqualFold(v, s) {
			*p = LogLevelValue(i)
			return
		}
	}
	*p = INFO

}

func (p *LogLevelValue) String() string {
	return levelNames[*p]
}

// Stores the log level to use. The default is ERROR
var LogLevel LogLevelValue = ERROR

// any is an alias for interface{} and is equivalent to interface{} in all ways.
type any = interface{}

func Tracef(ctx *context.Context, str string, v ...any) {
	logF(ctx, TRACE, str, v...)
}

func Traceln(ctx *context.Context, v ...any) {
	logN(ctx, TRACE, v...)
}
func Debugf(ctx *context.Context, str string, v ...any) {
	logF(ctx, DEBUG, str, v...)
}

func Debugln(ctx *context.Context, v ...any) {
	logN(ctx, DEBUG, v...)
}
func Infof(ctx *context.Context, str string, v ...any) {
	logF(ctx, INFO, str, v...)
}

func Infoln(ctx *context.Context, v ...any) {
	logN(ctx, INFO, v...)
}

func Warnf(ctx *context.Context, str string, v ...any) {
	logF(ctx, WARN, str, v...)
}

func Warnln(ctx *context.Context, v ...any) {
	logN(ctx, WARN, v...)
}
func Fatal(v ...any) {
	fatal(v...)
}

func Errorf(ctx *context.Context, str string, v ...any) {
	logF(ctx, ERROR, str, v...)
}

func Errorln(ctx *context.Context, v ...any) {
	logN(ctx, ERROR, v...)
}

func logF(ctx *context.Context, level LogLevelValue, str string, v ...any) {
	pc, _, _, ok := runtime.Caller(2)
	_logF(ctx, pc, ok, level, str, LogLevel, v...)
}

func _funcName(pc uintptr) string {
	name := runtime.FuncForPC(pc).Name()
	return name[strings.LastIndex(name, "/")+1:]
}

func _logF(ctx *context.Context, pc uintptr, ok bool, level LogLevelValue, str string, currentLogLevel LogLevelValue, v ...any) {
	var color int
	var name string
	var user types.SqlUuid
	var userOk bool
	if ok {
		name = _funcName(pc)
	}

	switch level {
	case TRACE:
		color = Cyan
	case ERROR, FATAL:
		color = Red
	case DEBUG:
		color = Magenta
	case WARN:
		color = Yellow
	case INFO:
		color = Green
	}

	l := &LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     levelNames[level],
		Caller:    name,
		Message:   fmt.Sprintf(str, v...),
		Env:       Environment,
	}
	if ctx != nil {
		if user, userOk = (*ctx).Value(contextkeys.CtxKeyUser).(types.SqlUuid); userOk {
			l.User = user.String()
		}

	}

	logEntryBytes, _ := json.Marshal(l)

	if level >= currentLogLevel {
		if format == RAW {
			printf(Colourize(fmt.Sprintf("%-5s [%s] %s", levelNames[level], name, str), color), v...)

		} else {
			// kk := []interface{}{string(logEntryBytes)}

			std.Output(2, string(logEntryBytes))

		}
	}
}

func logN(ctx *context.Context, level LogLevelValue, v ...any) {
	pc, _, _, ok := runtime.Caller(2)
	_logN(ctx, pc, ok, level, LogLevel, v...)
}

func _logN(ctx *context.Context, pc uintptr, ok bool, level LogLevelValue, currentLogLevel LogLevelValue, v ...any) {
	var color int
	var name string
	var user types.SqlUuid
	var userOk bool
	if ok {
		name = _funcName(pc)
	}

	switch level {
	case TRACE:
		color = Cyan
	case ERROR, FATAL:
		color = Red
	case DEBUG:
		color = Magenta
	case WARN:
		color = Yellow
	case INFO:
		color = Green

	}

	if level >= currentLogLevel {
		var kk []interface{}
		if format == JSON {
			l := &LogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				Level:     levelNames[level],
				Caller:    name,
				Message:   fmt.Sprint(v...),
				Env:       Environment,
			}
			if ctx != nil {
				if user, userOk = (*ctx).Value(contextkeys.CtxKeyUser).(types.SqlUuid); userOk {
					l.User = user.String()
				}

			}
			logEntryBytes, _ := json.Marshal(l)

			// kk = []interface{}{fmt.Sprintf("%-5s ", levelNames[level]), string(logEntryBytes)}
			std.Output(2, string(logEntryBytes))

		} else {
			kk = []interface{}{fmt.Sprintf("%-5s ", levelNames[level]), fmt.Sprintf("[%s] ", name), v}
			println(color, kk...)

			// kk = append(kk, v...)
		}

	}
}
func Println(ctx *context.Context, v ...any) {
	logN(ctx, INFO, v...)
}

// Printf calls Output to print to the standard logger.
// Arguments are handled in the manner of fmt.Printf.
func Printf(ctx *context.Context, format string, v ...any) {
	logF(ctx, INFO, format, v...)
}
