package messageprocessor

import "github.com/carbonblack/cb-event-forwarder/internal/cbapi"

type Config struct {
	DebugFlag   bool
	DebugStore  string
	CbServerURL string
	EventMap    map[string]interface{}
	CbAPI       *cbapi.CbAPIHandler
}
