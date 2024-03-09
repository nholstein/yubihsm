package yubihsm

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

//go:embed testdata/*.log
var testdataLogs embed.FS

var matchConnectorLogLine = regexp.MustCompile(`^DEBU\[\d{4}\]\susb endpoint (\w+).*buf="\[((\d|\s)*)\]"`)

type testConnector interface {
	Connector
	flush()
}

// replayConnector allows replaying a series of commands & responses to
// a YubiHSM2.
//
// Because all messages exchanged are 100% deterministic if the host and
// card challenges are known (along with the device's authentication key)
// the exact messages can be recreated. This allows capturing messages
// from either snooping traffic to real YubiHSM2, or from an alternative
// software solution such as yubihsm.rs or yubihsm-go.
//
// The primary limitation is that messages must match _exactly. The order
// and any parameters must be bit-for-bit identical. The benefit is that
// a [Session] can be deterministically verified.
type replayConnector struct {
	T
	messages [][2][]byte
}

// flush all unsent messages to prevent a test from raising an error due
// to un-replayed messages.
func (r *replayConnector) flush() {
	r.messages = nil
}

// loadReplayConnector parses the debug logs from yubihsm-connector to
// allow replaying a series of command/response message exchanges.
//
// To record a series of messages run the connector in debug mode:
//
//	yubihsm-connector --debug
//
// Use yubihsm-shell or the equivalent to send commands to the YubiHSM.
// Then cut-n-paste the results into log file under testdata and go:embed
// the data into a test.
//
// A few notes:
//
//   - It isn't necessary to capture the full output; you only need to
//     copy the relevant section of messages. For example, you could use
//     a single yubihsm-shell command to perform some test setup (e.g.,
//     generate keys) and then run the commands to log.
//
//   - In most cases, you'll want to log a full session. Look for the
//     create-session command line matching:
//     DEBU[xxx] usb endpoint write   ...   buf="[3 0 10
//
//   - Beware of echo commands generated by yubihsm-shell. In addition
//     to the ~15 second keepalive ping, yubihsm-shell also appears to
//     send an echo command immediately before each message.
//
//     Because the echo commands are encrypted within a session, it's
//     difficult to check if a logged command is an echo. However, an
//     echo command from yubihsm-shell is always 28 bytes in length.
func loadReplayConnector(t T, yubihsmConnectorLog string) *replayConnector {
	log, err := testdataLogs.Open("testdata/" + yubihsmConnectorLog)
	if err != nil {
		t.Helper()
		t.Fatalf("could not load testdata/%s: %v", yubihsmConnectorLog, err)
	}
	return loadReplayConnectorReader(t, log, yubihsmConnectorLog)
}

func loadReplayConnectorReader(t T, yubihsmConnectorLog io.Reader, name string) *replayConnector {
	r := replayConnector{T: t}
	lines := bufio.NewScanner(yubihsmConnectorLog)

	for {
		direction, command := parseUsbEndpointLine(lines)
		if direction == "" {
			// End of logs
			break
		} else if direction == "read" && len(command) == 0 {
			t.Logf("ignoring empty read (flush USB endpoint)")
			continue
		} else if direction != "write" {
			t.Errorf("expected \"write\" command, found: %q", direction)
		}

		direction, response := parseUsbEndpointLine(lines)
		if direction == "" {
			t.Errorf("truncated logs; no \"read\" response event")
			break
		} else if direction != "read" {
			t.Errorf("did not parse \"read\" response event")
			continue
		}

		r.messages = append(r.messages, [2][]byte{command, response})
	}

	if lines.Err() != nil {
		t.Helper()
		t.Fatalf("failed to read yubihsm-connector logs: %v", lines.Err())
	} else if len(r.messages) == 0 {
		t.Helper()
		t.Fatalf("failed to load any command/response pairs from yubihsm-connector logs")
	}

	t.Cleanup(func() {
		if len(r.messages) != 0 {
			t.Errorf("warning: %d command/response pairs remain un-replayed", len(r.messages))
		}
	})

	t.Logf("loaded %d command/response pairs from yubihsm-connector logs %q", len(r.messages), name)
	return &r
}

func parseUsbEndpointLine(lines *bufio.Scanner) (string, []byte) {
	for lines.Scan() {
		matches := matchConnectorLogLine.FindSubmatch(lines.Bytes())
		if len(matches) == 0 {
			continue
		}

		return string(matches[1]), parseLoggedBytes(matches[2])
	}
	return "", nil
}

func parseLoggedBytes(match []byte) (message []byte) {
	for _, m := range strings.Fields(string(match)) {
		b, _ := strconv.Atoi(m)
		message = append(message, byte(b))
	}
	return
}

func (r *replayConnector) findHostChallenges(t T) [][8]byte {
	var hostChallenges [][8]byte
	for _, m := range r.messages {
		if m[0][0] == byte(yubihsm.CommandCreateSession) &&
			len(m[0]) == 1+2+2+8 {
			var hostChallenge [8]byte
			copy(hostChallenge[:], m[0][5:13])
			t.Logf("found logged CreateSession.HostChallenge: %x", hostChallenge)
			hostChallenges = append(hostChallenges, hostChallenge)
		}
	}
	return hostChallenges
}

func (r *replayConnector) findHostChallenge(t T) [8]byte {
	hostChallenges := r.findHostChallenges(t)
	if len(hostChallenges) == 0 {
		t.Fatalf("could not recover CreateSession.HostChallenge in replayConnector messages")
	} else if len(hostChallenges) > 1 {
		t.Fatalf("expected a single host challenge, found %d", len(hostChallenges))
	}
	return hostChallenges[0]
}

func (r *replayConnector) SendCommand(ctx context.Context, cmd []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	default:
		r.Logf("replay:")
		r.Logf("    -> %x", cmd)
		if len(r.messages) == 0 {
			return nil, errors.New("reached end of logged messages")
		} else if !bytes.Equal(cmd, r.messages[0][0]) {
			return nil, fmt.Errorf("mismatch:\n   (%d) %x\n   (%d) %x", len(cmd), cmd, len(r.messages[0][0]), r.messages[0][0])
		}
		rsp := r.messages[0][1]
		r.Logf("    <- %x", rsp)
		r.messages = r.messages[1:]
		return rsp, nil
	}
}

// Used to record logs from a real YubiHSM2 for replayConnector.
type logMessagesConnector struct {
	T
	msgs [][2][]byte
	http HTTPConnector
}

func (l *logMessagesConnector) SendCommand(ctx context.Context, cmd []byte) ([]byte, error) {
	rsp, err := l.http.SendCommand(ctx, cmd)
	l.msgs = append(l.msgs, [2][]byte{yubihsm.Append(nil, cmd), yubihsm.Append(nil, rsp)})
	l.Logf("recorded:")
	l.Logf("    -> %x", cmd)
	l.Logf("    <- %x", rsp)
	return rsp, err
}

func (l *logMessagesConnector) flush() {
	l.Logf("logMessagesConnector.flush()")
}

func (l *logMessagesConnector) cleanup(t T, logName string) {
	t.Cleanup(func() { l.saveTestdata(t, logName) })
}

func (l *logMessagesConnector) saveTestdata(t T, logName string) {
	if test, ok := t.(*testing.T); ok && test.Failed() {
		return
	}

	file, err := os.Create("testdata/" + logName)
	defer func() {
		err = file.Close()
		if err != nil {
			t.Errorf("%s.Close(): %v", logName, err)
		}
	}()

	for i, msg := range l.msgs {
		_, err = fmt.Fprintf(file,
			"DEBU[%04d] usb endpoint write  buf=\"%d\"\n"+
				"DEBU[%04d] usb endpoint read   buf=\"%d\"\n",
			2*i+1, msg[0], 2*i+2, msg[1],
		)
		if err != nil {
			t.Errorf("%s.Write(): %v", logName, err)
		}
	}
}
