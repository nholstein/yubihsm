package yubihsm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func httpServerReplay(t *testing.T, log string, options ...AuthenticationOption) (context.Context, *httptest.Server, []AuthenticationOption) {
	ctx, conn, options := loadReplay(t, log, options...)
	mux := http.NewServeMux()
	mux.HandleFunc("/foobar", func(w http.ResponseWriter, req *http.Request) {
		ct := req.Header.Get("Content-Type")
		if ct != "application/octet-stream" && !strings.HasPrefix(ct, "application/octet-stream;") {
			t.Errorf("incorrect Content-Type: %q", ct)
		}
		cmd, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			w.WriteHeader(400)
			return
		}
		rsp, err := conn.SendCommand(req.Context(), cmd)
		if err != nil {
			t.Errorf("send command: %v", err)
			w.WriteHeader(500)
			return
		}
		_, err = w.Write(rsp)
		if err != nil {
			t.Errorf("write response: %v", err)
			return
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return ctx, server, options
}

func TestHTTPConnector(t *testing.T) {
	ctx, server, options := httpServerReplay(t, "session-open-close.log")
	conn := NewHTTPConnector(
		WithHTTPClient(server.Client()),
		WithConnectorURL(server.URL+"/foobar"),
	)

	var session Session
	testAuthenticate(ctx, t, &conn, &session, options...)
	testSendPing(ctx, t, &conn, &session)
	testSessionClose(ctx, t, &conn, &session)
}

type errTransport struct{ error }

func (e *errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.error
}

func TestHTTPConnectorErrors(t *testing.T) {
	t.Run("bad URL", func(t *testing.T) {
		ctx := testingContext(t)
		conn := NewHTTPConnector(WithConnectorURL("http://localhost\n:12345/"))
		var session Session
		_, err := session.GetDeviceInfo(ctx, &conn)
		var uErr *url.Error
		if !errors.As(err, &uErr) {
			t.Errorf("should have received a url.Error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		wompWompWaaaah := errors.New("womp womp waaaah")
		ctx := testingContext(t)
		client := http.Client{
			Transport: &errTransport{wompWompWaaaah},
		}
		conn := NewHTTPConnector(WithHTTPClient(&client))

		var session Session
		_, err := session.GetDeviceInfo(ctx, &conn)
		if !errors.Is(err, wompWompWaaaah) {
			t.Errorf("should have received the transport error")
		}
	})

	t.Run("not found", func(t *testing.T) {
		ctx := testingContext(t)
		server := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(server.Close)

		conn := NewHTTPConnector(
			WithHTTPClient(server.Client()),
			WithConnectorURL(server.URL+"/not-here"),
		)

		var session Session
		err := session.Authenticate(ctx, &conn)
		if !strings.HasSuffix(err.Error(), "404 Not Found") {
			t.Errorf("expected not-found, got: %v", err)
		}
	})
}
