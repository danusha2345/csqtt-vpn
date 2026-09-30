package core

import "encoding/binary"

// Validate IP framing before handing an untrusted transport datagram to Wintun.
func isIPPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return false
		}
		header := int(packet[0]&15) * 4
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		return header >= 20 && header <= total && total <= len(packet)
	case 6:
		return len(packet) >= 40 && 40+int(binary.BigEndian.Uint16(packet[4:6])) <= len(packet)
	default:
		return false
	}
}

// Invalid packets and packet-specific errors do not kill the bridge.
// Device and permission errors are returned to the existing fail-safe cleanup.
func forwardIPPacket(packet []byte, write func([]byte) (int, error), rejected func(error) bool) (bool, error) {
	if !isIPPacket(packet) {
		return false, nil
	}
	written, err := write(packet)
	if err != nil {
		if rejected(err) {
			return false, nil
		}
		return false, err
	}
	return written == 1, nil
}
