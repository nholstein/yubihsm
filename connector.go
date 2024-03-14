package yubihsm

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

// DeviceInfo contains information about the HSM.
//
// https://developers.yubico.com/YubiHSM2/Commands/Device_Info.html
type DeviceInfo struct {
	// Version string. Received from the HSM.
	Version string
	// Serial number. Received from the HSM.
	Serial uint32
	// LogStore size expressed in number of log entries. Received from
	// the HSM.
	LogStore uint8
	// LogLines used. Received from the HSM.
	LogLines uint8
	// Algorithms supported by the device. Received from the HSM.
	Algorithms uint64
	// Trusted is set to [true] if and only if the information was
	// received via an authenticated and encrypted [Session].
	Trusted bool
}

// Connector allows sending commands to a YubiHSM2.
//
// [command] is a fully serialized [HSM command]. The YubiHSM2 has a
// maximum command length of 2028 bytes per the documentation of the [Put
// Opaque] command; therefore a connector must support sending a message
// this long.
//
// [HSM command]: https://developers.yubico.com/YubiHSM2/Commands/
// [Put Opaque]: https://developers.yubico.com/YubiHSM2/Commands/Put_Opaque.html
type Connector interface {
	SendCommand(ctx context.Context, command []byte) ([]byte, error)
}

// HTTPConnector is a [Connector] which provides access to a YubiHSM2
// through the [yubihsm-connector] HTTP interface.
//
// The zero value HTTPConnector is valid to use and connects to the
// yubihsm-connector at http://localhost:12345/connector/api using
// [net/http.DefaultClient]. This behavior can be customized with
// [NewHTTPConnector].
//
// [yubihsm-connector]: https://github.com/Yubico/yubihsm-connector/
type HTTPConnector struct {
	client *http.Client
	url    string
}

type httpConnector HTTPConnector

// HTTPOption configures the behavior of the [HTTPConnector] created by
// [NewHTTPConnector].
type HTTPOption func(*httpConnector)

// NewHTTPConnector creates an [HTTPConnector] using the provided
// configuration options.
func NewHTTPConnector(options ...HTTPOption) HTTPConnector {
	var conn httpConnector
	for _, option := range options {
		option(&conn)
	}

	return (HTTPConnector)(conn)
}

// WithHTTPClient configures the [HTTPConnector] to make HTTP requests
// using the provided HTTP client.
//
// If not specified this defaults to [http.DefaultClient].
func WithHTTPClient(client *http.Client) HTTPOption {
	return func(conn *httpConnector) {
		conn.client = client
	}
}

// WithConnectorURL configures the [HTTPConnector] to issue HTTP requests
// to the yubihsm-connector at the provided URL.
//
// If not specified this defaults to "http://localhost:12345/connector/api".
//
//	NewHTTPConnector(WithConnectorURL("http://1.2.3.4:5678/connector/api"))
func WithConnectorURL(url string) HTTPOption {
	return func(conn *httpConnector) {
		conn.url = url
	}
}

// SendCommand transmits the command and returns the YubiHSM2's response.
func (h *HTTPConnector) SendCommand(ctx context.Context, cmd []byte) ([]byte, error) {
	client := cmp.Or(h.client, http.DefaultClient)
	url := cmp.Or(h.url, "http://localhost:12345/connector/api")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(cmd))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	rsp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rsp.Body.Close() }()

	if rsp.StatusCode < http.StatusOK || rsp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("connector command failed: %s", rsp.Status)
	}

	return io.ReadAll(rsp.Body)
}

func sendPlaintext(ctx context.Context, conn Connector, cmd yubihsm.Command, rsp yubihsm.Response) error {
	// While the largest command supported is ~2kB, this is large
	// enough to hold authentication messages without spilling to
	// the heap.
	var out [32]byte

	buf, err := conn.SendCommand(ctx, cmd.Serialize(out[:0]))
	if err != nil {
		return err
	}

	return yubihsm.ParseResponse(cmd.ID(), rsp, buf)
}
