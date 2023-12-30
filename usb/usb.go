// Package usb provides access to a YubiHSM2 attached via USB.
//
// It uses the [gousb] package to communicate over USB. As a result it
// requires use of CGo to build.
//
// [gousb]: https://github.com/google/gousb#introduction
package usb

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gousb"
)

const (
	yubihsmVID = 0x1050
	yubihsmPID = 0x0030
)

// trimSerial returns the canonical device serial number. The serial is
// a 32-bit integer as seen by the device-info command. When sent over
// USB the serial number is decimal number 0-padded to ten digits. To
// ensure these are matched correctly, trim leading zeros.
func trimSerial(serial string) string {
	return strings.TrimLeft(serial, "0")
}

// Option customizes the behavior of [OpenDevice].
type Option func(*config)

type config struct {
	// optional serial number.
	serial string

	// optional USB context.
	ctx *gousb.Context

	// optional USB context to close within [Device.Close].
	cCtx *gousb.Context
}

// WithUSBContext allows specifying a [gousb.Context] for use when opening
// a USB device. If a context is provided it must be manually closed after
// closing any opened devices.
func WithUSBContext(ctx *gousb.Context) Option {
	return func(c *config) { c.ctx = ctx }
}

// WithDeviceSerial will only open a YubiHSM2 with the given serial number.
// A serial number of 0 is ignored.
func WithDeviceSerial(serial uint32) Option {
	return func(c *config) {
		if serial != 0 {
			c.serial = strconv.FormatUint(uint64(serial), 10)
		}
	}
}

// OpenDevice connects to a YubiHSM2 via USB.
func OpenDevice(ctx context.Context, options ...Option) (*Device, error) {
	var c config
	for _, o := range options {
		o(&c)
	}

	return c.openDevice(ctx)
}

func (c *config) openDevice(ctx context.Context) (d *Device, err error) {
	if c.ctx == nil {
		c.cCtx = gousb.NewContext()
		c.ctx = c.cCtx

		defer func() {
			if err != nil {
				_ = c.cCtx.Close()
			}
		}()
	}

	if c.serial == "" {
		return c.openAny(ctx)
	}

	return c.openSerial(ctx, c.serial)
}

func (c *config) openAny(ctx context.Context) (d *Device, err error) {
	dev, err := c.ctx.OpenDeviceWithVIDPID(yubihsmVID, yubihsmPID)
	switch {
	case dev != nil:
		defer func() {
			if err != nil {
				_ = dev.Close()
			}
		}()

		var serial string
		serial, err = dev.SerialNumber()
		if err != nil {
			return nil, err
		}

		return c.initDevice(ctx, dev, trimSerial(serial))

	case err != nil:
		return nil, err

	default:
		return nil, syscall.ENOSYS
	}
}

func (c *config) openSerial(ctx context.Context, serial string) (*Device, error) {
	// OpenDevices can return an error alongside a list of devices.
	// Suppress this error if we successfully open a device.
	devs, openErr := c.ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		return desc.Vendor == yubihsmVID && desc.Product == yubihsmPID
	})

	for i, dev := range devs {
		serial, _ := dev.SerialNumber()
		serial = trimSerial(serial)

		if serial != c.serial {
			_ = dev.Close()
			continue
		}

		d, err := c.initDevice(ctx, dev, serial)
		closeDevs(devs[i:], err)

		return d, err
	}

	return nil, errors.Join(fmt.Errorf("YubiHSM2 with serial %q not found", serial), openErr) //nolint:err113
}

func closeDevs(devs []*gousb.Device, err error) {
	if err == nil {
		devs = devs[1:]
	}

	for _, dev := range devs {
		_ = dev.Close()
	}
}

func (c *config) initDevice(ctx context.Context, dev *gousb.Device, serial string) (d *Device, err error) {
	iface, done, err := dev.DefaultInterface()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			done()
		}
	}()

	in, err := iface.InEndpoint(0x81)
	if err != nil {
		return nil, err
	}

	out, err := iface.OutEndpoint(0x01)
	if err != nil {
		return nil, err
	}

	// Flush any write buffers on the YubiHSM2; to clear out any
	// responses remaining from a previous client.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	_, _ = readUSB(ctx, in)

	return &Device{serial, c.cCtx, dev, iface, done, in, out}, nil
}

// Device is a YubiHSM2 connected via USB.
type Device struct {
	serial string
	ctx    *gousb.Context
	dev    *gousb.Device
	iface  *gousb.Interface
	done   func()
	in     *gousb.InEndpoint
	out    *gousb.OutEndpoint
}

// String implements [fmt.Stringer]. It returns the HSM serial number.
func (d *Device) String() string {
	return "YubiHSM2 " + d.serial
}

// Close implements [io.Closer]. It closes the connection to the HSM and
// releases all operating system resources.
//
// If the caller provided a USB context with [WithUSBContext] when opening
// the devices then this must be called prior to closing the USB context.
func (d *Device) Close() error {
	d.done()
	err := d.dev.Close()

	// Only close the context if it was created within [OpenDevice].
	if d.ctx == nil {
		return err
	}

	return errors.Join(err, d.ctx.Close())
}

// SendCommand implements [yubihsm.Connector]. It sends the [command] to
// the YubiHSM2 via USB and waits for the response.
func (d *Device) SendCommand(ctx context.Context, command []byte) ([]byte, error) {
	// WriteContext may return partial writes, so add retry logic.
	for len(command) > 0 {
		n, err := d.out.WriteContext(ctx, command)
		if err != nil {
			return nil, err
		}
		command = command[n:]
	}

	return readUSB(ctx, d.in)
}

func readUSB(ctx context.Context, in *gousb.InEndpoint) ([]byte, error) {
	// The maximum packet length is 2028 byte according to the HSM
	// documentation. Round up to the next multiple of the maximum
	// packet size (64 bytes) to ensure a complete read.
	var buf [2048]byte

	n, err := in.ReadContext(ctx, buf[:])
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}
