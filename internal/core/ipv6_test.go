package core

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"nodekit/internal/model"
)

func ipv6HealthClient(t *testing.T) *Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "ip6-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "core.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &Client{Socket: socket}
}

func ipv6HealthConfig(typ, address string, port int) model.Config {
	return model.Config{Protocols: []model.Protocol{{Type: typ, Port: port}}, IPv6Nodes: &model.IPv6NodesConfig{Enabled: true, Address: address, Protocols: []string{typ}, IPv4ListenAddresses: []string{"127.0.0.1"}}}
}

func TestIPv6HealthRejectsWrongFamilyAddressAndPort(t *testing.T) {
	client := ipv6HealthClient(t)
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp6" {
				address = "[::1]:0"
			}
			l, err := net.Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			port := l.Addr().(*net.TCPAddr).Port
			cfg := ipv6HealthConfig("vless", "::1", port)
			if err = client.Health(context.Background(), cfg); (err == nil) != (network == "tcp6") {
				t.Fatalf("IPv6 health using %s: %v", network, err)
			}
			cfg.IPv6Nodes.Address = "2001:4860:4860::8888"
			if err = client.Health(context.Background(), cfg); err == nil {
				t.Fatal("same port on wrong IPv6 address satisfied health")
			}
			cfg.IPv6Nodes.Address = "::1"
			cfg.Protocols[0].Port = 0
			if err = client.Health(context.Background(), cfg); err == nil {
				t.Fatal("wrong port satisfied health")
			}
			cfg.Protocols[0].Port = port
			cfg.Protocols[0].Enabled = true
			cfg.IPv6Nodes.Enabled = false
			if err = client.Health(context.Background(), cfg); (err == nil) != (network == "tcp4") {
				t.Fatalf("explicit IPv4 health using %s: %v", network, err)
			}
			cfg.IPv6Nodes.IPv4ListenAddresses = []string{"127.0.0.2"}
			if err = client.Health(context.Background(), cfg); err == nil {
				t.Fatal("same port on wrong IPv4 address satisfied health")
			}
			cfg.IPv6Nodes = nil
			if err = client.Health(context.Background(), cfg); err != nil {
				t.Fatalf("legacy family-agnostic behavior changed: %v", err)
			}
		})
	}
}

func TestIPv6HealthRequiresEachSelectedProtocolTransport(t *testing.T) {
	client := ipv6HealthClient(t)
	for _, typ := range []string{"ss", "tuic", "hysteria2", "anytls"} {
		t.Run(typ, func(t *testing.T) {
			tcp, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			port := tcp.Addr().(*net.TCPAddr).Port
			cfg := ipv6HealthConfig(typ, "::1", port)
			if err = client.Health(context.Background(), cfg); (err == nil) != (typ == "anytls") {
				t.Fatalf("TCP-only %s health: %v", typ, err)
			}
			udp4, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			defer udp4.Close()
			if err = client.Health(context.Background(), cfg); (err == nil) != (typ == "anytls") {
				t.Fatalf("wrong-family UDP satisfied %s: %v", typ, err)
			}
			udp6, err := net.ListenPacket("udp6", fmt.Sprintf("[::1]:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			defer udp6.Close()
			if err = client.Health(context.Background(), cfg); err != nil {
				t.Fatalf("complete %s listener rejected: %v", typ, err)
			}
			tcp.Close()
			if err = client.Health(context.Background(), cfg); (err == nil) != (typ == "tuic" || typ == "hysteria2") {
				t.Fatalf("UDP-only %s health: %v", typ, err)
			}
			cfg.IPv6Nodes.Address = "2001:4860:4860::8888"
			if err = client.Health(context.Background(), cfg); err == nil {
				t.Fatal("wrong address satisfied UDP health")
			}
		})
	}
}

func TestIPv6HealthRequiresEveryExplicitIPv4Binding(t *testing.T) {
	client := ipv6HealthClient(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	cfg := ipv6HealthConfig("vless", "::1", port)
	cfg.Protocols[0].Enabled = true
	cfg.IPv6Nodes.Enabled = false
	cfg.IPv6Nodes.IPv4ListenAddresses = []string{"127.0.0.1", "127.0.0.2"}
	if err = client.Health(context.Background(), cfg); err == nil {
		t.Fatal("one IPv4 socket satisfied two explicit bindings")
	}
	l2, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.2:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if err = client.Health(context.Background(), cfg); err != nil {
		t.Fatal("complete explicit IPv4 listeners rejected", err)
	}
}

func TestIPv6HealthIPv4CannotSatisfyAdditionalIPv6(t *testing.T) {
	client := ipv6HealthClient(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cfg := ipv6HealthConfig("vless", "::1", l.Addr().(*net.TCPAddr).Port)
	cfg.Protocols[0].Enabled = true
	if err := client.Health(context.Background(), cfg); err == nil {
		t.Fatal("IPv4 original satisfied the additional same-port IPv6 listener")
	}
}

func TestIPv6HealthRejectsWildcardInsteadOfExplicitAddress(t *testing.T) {
	client := ipv6HealthClient(t)
	l, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cfg := ipv6HealthConfig("vless", "::1", l.Addr().(*net.TCPAddr).Port)
	if err := client.Health(context.Background(), cfg); err == nil {
		t.Fatal("IPv6 wildcard satisfied a specific IPv6 binding")
	}
}

func TestIPv6HealthRejectsConnectedUDPAsListener(t *testing.T) {
	client := ipv6HealthClient(t)
	target, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	connected, err := net.Dial("udp6", target.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	cfg := ipv6HealthConfig("tuic", "::1", connected.LocalAddr().(*net.UDPAddr).Port)
	if err := client.Health(context.Background(), cfg); err == nil {
		t.Fatal("connected outbound UDP socket satisfied a UDP listener")
	}
}

func TestIPv6HealthForeignSocketHelper(t *testing.T) {
	if os.Getenv("NODEKIT_IPV6_SOCKET_HELPER") != "1" {
		return
	}
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	u, err := net.ListenPacket("udp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	fmt.Println(port)
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestIPv6HealthRejectsOtherProcessSocketInodes(t *testing.T) {
	client := ipv6HealthClient(t)
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-test.run=^TestIPv6HealthForeignSocketHelper$")
	cmd.Env = append(os.Environ(), "NODEKIT_IPV6_SOCKET_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal("socket helper failed", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal("socket helper returned invalid port", line, err)
	}
	for _, typ := range []string{"ss", "vless", "tuic"} {
		if err := client.Health(context.Background(), ipv6HealthConfig(typ, "::1", port)); err == nil {
			t.Fatalf("other process's %s sockets satisfied core health", typ)
		}
	}
}

func TestIPv6ProcAddressesUseNativeEndianWords(t *testing.T) {
	littleEndian := binary.NativeEndian.Uint32([]byte{1, 0, 0, 0}) == 1
	for _, tc := range []struct{ little, big, want string }{
		{"0200007F", "7F000002", "127.0.0.2"},
		{"00000000000000000000000001000000", "00000000000000000000000000000001", "::1"},
		{"60480120000060480000000088880000", "20014860486000000000000000008888", "2001:4860:4860::8888"},
		{"0000000000000000FFFF00000100007F", "00000000000000000000FFFF7F000001", "::ffff:127.0.0.1"},
	} {
		raw := tc.big
		if littleEndian {
			raw = tc.little
		}
		got, err := procAddress(raw)
		if err != nil || got.String() != tc.want {
			t.Fatalf("%s: got %s (%v), want %s", raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{"", "0", "0000000000000000", "ZZ000000", "0000000000000000000000000000000Z"} {
		if _, err := procAddress(raw); err == nil {
			t.Fatalf("accepted malformed proc address %q", raw)
		}
	}
}
