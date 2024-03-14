package yubihsm_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nholstein/yubihsm"
)

func httpServerReplay(t *testing.T, log string, options ...yubihsm.AuthenticationOption) (context.Context, *httptest.Server, []yubihsm.AuthenticationOption) {
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
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rsp, err := conn.SendCommand(req.Context(), cmd)
		if err != nil {
			t.Errorf("send command: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
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
	t.Parallel()

	ctx, server, options := httpServerReplay(t, "session-open-close.log")
	conn := yubihsm.NewHTTPConnector(
		yubihsm.WithHTTPClient(server.Client()),
		yubihsm.WithConnectorURL(server.URL+"/foobar"),
	)

	var session yubihsm.Session
	testAuthenticate(ctx, t, &conn, &session, options...)
	testSendPing(ctx, t, &conn, &session)
	testSessionClose(ctx, t, &conn, &session)
}

type errTransport struct{ error }

func (e *errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.error
}

func TestHTTPConnectorErrors(t *testing.T) {
	t.Parallel()

	t.Run("bad URL", func(t *testing.T) {
		t.Parallel()

		ctx := testingContext(t)
		conn := yubihsm.NewHTTPConnector(yubihsm.WithConnectorURL("http://localhost\n:12345/"))
		var session yubihsm.Session
		_, err := session.GetDeviceInfo(ctx, &conn)
		var uErr *url.Error
		if !errors.As(err, &uErr) {
			t.Errorf("should have received a url.Error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		t.Parallel()

		wompWompWaaaah := errors.New("womp woomp waaaah")
		ctx := testingContext(t)
		client := http.Client{
			Transport: &errTransport{wompWompWaaaah},
		}
		conn := yubihsm.NewHTTPConnector(yubihsm.WithHTTPClient(&client))

		var session yubihsm.Session
		_, err := session.GetDeviceInfo(ctx, &conn)
		if !errors.Is(err, wompWompWaaaah) {
			t.Errorf("should have received the transport error")
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()

		ctx := testingContext(t)
		server := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(server.Close)

		conn := yubihsm.NewHTTPConnector(
			yubihsm.WithHTTPClient(server.Client()),
			yubihsm.WithConnectorURL(server.URL+"/not-here"),
		)

		var session yubihsm.Session
		err := session.Authenticate(ctx, &conn)
		if !strings.HasSuffix(err.Error(), "404 Not Found") {
			t.Errorf("expected not-found, got: %v", err)
		}
	})
}
