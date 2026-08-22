package agent

import (
	"encoding/json"
	"io"
	"os"
)

// Sink is where module output goes. Modules never see sinks directly; the
// Runner fans every module's Events() into all configured sinks.
type Sink interface {
	Write(Event) error
}

type jsonSink struct {
	enc *json.Encoder
}

// NewJSONSink writes one JSON object per line to w.
func NewJSONSink(w io.Writer) Sink {
	return &jsonSink{enc: json.NewEncoder(w)}
}

// NewStdoutJSON writes one JSON object per event to stdout.
func NewStdoutJSON() Sink {
	return NewJSONSink(os.Stdout)
}

func (s *jsonSink) Write(e Event) error {
	return s.enc.Encode(e)
}
