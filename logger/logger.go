package logger

import (
	"github.com/travelata/auth/meta"
	"github.com/travelata/kit/log"
)

var Logger = log.Init(&log.Config{Level: log.TraceLevel})

func LF() log.CLoggerFunc {
	return func() log.CLogger {
		return log.L(Logger).Srv(meta.Meta.InstanceId())
	}
}

func L() log.CLogger {
	return LF()()
}
