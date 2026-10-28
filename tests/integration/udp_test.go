package integration

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func udpEcho(t *testing.T) string {
	t.Helper()
	pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := pc.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], a)
		}
	}()
	return pc.LocalAddr().String()
}
func udpRoundTrip(t *testing.T, port int, target string) {
	t.Helper()
	c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 2)
	if _, e = io.ReadFull(c, reply); e != nil || !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatal("SOCKS authentication", reply, e)
	}
	_, e = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if e != nil {
		t.Fatal(e)
	}
	head := make([]byte, 4)
	if _, e = io.ReadFull(c, head); e != nil || head[1] != 0 {
		t.Fatal("UDP associate", head, e)
	}
	n := 4
	if head[3] == 4 {
		n = 16
	} else if head[3] != 1 {
		t.Fatal("unsupported SOCKS bind address")
	}
	tail := make([]byte, n+2)
	if _, e = io.ReadFull(c, tail); e != nil {
		t.Fatal(e)
	}
	bindPort := int(binary.BigEndian.Uint16(tail[n:]))
	u, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bindPort})
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(10 * time.Second))
	dest, e := net.ResolveUDPAddr("udp4", target)
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte("nodekit-udp-roundtrip")
	packet := []byte{0, 0, 0, 1}
	packet = append(packet, dest.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(dest.Port))
	packet = append(packet, payload...)
	if _, e = u.Write(packet); e != nil {
		t.Fatal(e)
	}
	buffer := make([]byte, 4096)
	count, e := u.Read(buffer)
	if e != nil {
		t.Fatal("UDP proxy transfer", e)
	}
	if count < 10 || !bytes.Equal(buffer[count-len(payload):count], payload) {
		t.Fatal("UDP payload mismatch")
	}
}
