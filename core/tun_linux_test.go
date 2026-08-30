//go:build linux

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseLinuxDefaultRoute(t *testing.T) {
	route, err := parseLinuxDefaultRoute([]byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"}]`))
	if err != nil || route.Gateway != "192.0.2.1" || route.Dev != "eth0" {
		t.Fatalf("route=%+v err=%v", route, err)
	}
	if _, err := parseLinuxDefaultRoute([]byte(`[]`)); err == nil {
		t.Fatal("empty default route accepted")
	}
}

func TestSendLinuxTUNPassesDescriptor(t *testing.T) {
	name := fmt.Sprintf("csqtt-test-%d", time.Now().UnixNano())
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "\x00" + name, Net: "unix"})
	if errors.Is(err, unix.EPERM) {
		t.Skip("sandbox forbids abstract Unix sockets")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	source, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.WriteString("ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	received := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			received <- err
			return
		}
		defer conn.Close()
		data, control := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
		_, controlN, _, _, err := conn.ReadMsgUnix(data, control)
		if err != nil {
			received <- err
			return
		}
		messages, err := unix.ParseSocketControlMessage(control[:controlN])
		if err != nil || len(messages) != 1 {
			received <- fmt.Errorf("control messages=%d: %w", len(messages), err)
			return
		}
		fds, err := unix.ParseUnixRights(&messages[0])
		if err != nil || len(fds) != 1 {
			received <- fmt.Errorf("descriptors=%d: %w", len(fds), err)
			return
		}
		copy := os.NewFile(uintptr(fds[0]), "received")
		defer copy.Close()
		payload := make([]byte, 2)
		_, err = copy.Read(payload)
		if err == nil && string(payload) != "ok" {
			err = fmt.Errorf("payload=%q", payload)
		}
		received <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendLinuxTUN(ctx, name, source); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
}

func TestCreateLinuxTUN(t *testing.T) {
	if os.Getenv("CSQTT_TEST_TUN") != "1" {
		t.Skip("set CSQTT_TEST_TUN=1 inside an isolated network namespace")
	}
	file, err := createLinuxTUN()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := net.InterfaceByName(linuxTunName); err != nil {
		t.Fatalf("TUN interface is missing: %v", err)
	}
}
