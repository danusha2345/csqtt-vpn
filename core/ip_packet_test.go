package core

import (
	"errors"
	"testing"
)

func TestBridgeDropsNoiseAndRejectedPacketThenForwardsIP(t *testing.T) {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[3] = 20
	rejected := errors.New("invalid packet")
	fatal := errors.New("device closed")
	calls := 0
	write := func([]byte) (int, error) {
		calls++
		if calls == 1 {
			return 0, rejected
		}
		return 1, nil
	}
	classify := func(err error) bool { return errors.Is(err, rejected) }
	for _, packet := range [][]byte{nil, {0xff}, {0x45, 0, 0, 20}, make([]byte, 40)} {
		forwarded, err := forwardIPPacket(packet, write, classify)
		if forwarded || err != nil {
			t.Fatalf("noise reached bridge: %v %v", forwarded, err)
		}
	}
	if calls != 0 {
		t.Fatal("noise was written")
	}
	forwarded, err := forwardIPPacket(ip, write, classify)
	if forwarded || err != nil {
		t.Fatal("packet rejection should allow next packet")
	}
	forwarded, err = forwardIPPacket(ip, write, classify)
	if !forwarded || err != nil {
		t.Fatal("valid IP not forwarded after rejection")
	}
	_, err = forwardIPPacket(ip, func([]byte) (int, error) { return 0, fatal }, classify)
	if !errors.Is(err, fatal) {
		t.Fatal("fatal device error was swallowed")
	}
}

func TestIPPacketChecksDeclaredLengths(t *testing.T) {
	v6 := make([]byte, 48)
	v6[0] = 0x60
	v6[5] = 8
	if !isIPPacket(v6) || isIPPacket(v6[:47]) {
		t.Fatal("IPv6 length check")
	}
	v4 := make([]byte, 24)
	v4[0] = 0x45
	v4[3] = 24
	if !isIPPacket(v4) || isIPPacket(v4[:23]) {
		t.Fatal("IPv4 length check")
	}
	v4[0] = 0x4f
	if isIPPacket(v4) {
		t.Fatal("oversized IPv4 header accepted")
	}
}
