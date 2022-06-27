package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Error struct {
	StatusCode int    `json:"-"`
	TraceID    string `json:"-"`

	ErrorCode   string `json:"error,omitempty"`
	Description string `json:"error_description,omitempty"`
	Hint        string `json:"error_hint,omitempty"`
	Cause       string `json:"cause,omitempty"`
}

func (e *Error) Error() string {
	var output strings.Builder

	if e.StatusCode != 0 {
		output.WriteString(fmt.Sprintf("%d: ", e.StatusCode))
	}

	if e.Cause != "" {
		output.WriteString(fmt.Sprintf("%s caused by %s ", e.ErrorCode, e.Cause))
		return fmt.Sprintf("%d: %s caused by %s (%s)", e.StatusCode, e.ErrorCode, e.Cause, e.TraceID)
	} else {
		output.WriteString(fmt.Sprintf("%s ", e.ErrorCode))
	}

	if e.TraceID != "" {
		output.WriteString(fmt.Sprintf("(%s)", e.TraceID))
	}

	return strings.TrimSpace(output.String())
}

func ParseError(resp *http.Response) error {
	var (
		payload Error
		err     error
	)

	payload.StatusCode = resp.StatusCode
	payload.TraceID = resp.Header.Get("X-Trace-ID")

	if err = json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	return &payload
}
