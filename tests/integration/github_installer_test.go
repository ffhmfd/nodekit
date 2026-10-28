package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitHubInstallerPinsReleaseAndVerifiesAsset(t *testing.T) {
	for _, tc := range []struct{ name, arch, version, asset string }{
		{"latest-amd64", "x86_64", "", "amd64"},
		{"explicit-arm64", "aarch64", "v0.2.0", "arm64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "requests")
			os.WriteFile(filepath.Join(dir, "uname"), []byte("#!/bin/sh\necho "+tc.arch+"\n"), 0700)
			curl := `#!/bin/bash
set -eu
url=''; out=''
while (($#)); do
 case "$1" in
  -o|--output) out=$2; shift 2;;
  https://*) url=$1; shift;;
  *) shift;;
 esac
done
printf '%s\n' "$url" >> "$REQUEST_LOG"
case "$url" in
 */releases/latest) data='{"tag_name":"v0.2.0","draft":false,"prerelease":false}';;
 */SHA256SUMS) data='0000000000000000000000000000000000000000000000000000000000000000  nodekit-v0.2.0-linux-'"$ASSET_ARCH"'.tar.gz';;
 *.tar.gz) data='deliberately corrupted archive';;
 *) exit 42;;
esac
if [[ -n $out ]]; then printf '%s\n' "$data" > "$out"; else printf '%s\n' "$data"; fi
`
			os.WriteFile(filepath.Join(dir, "curl"), []byte(curl), 0700)
			args := []string{filepath.Join("..", "..", "install.sh"), "--repo", "sample/nodekit", "--non-interactive"}
			if tc.version != "" {
				args = append(args, "--version", tc.version)
			}
			cmd := exec.Command("bash", args...)
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "REQUEST_LOG="+log, "ASSET_ARCH="+tc.asset)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "FAILED") {
				t.Fatalf("download not checksum-verified: %v %s", err, out)
			}
			requests, _ := os.ReadFile(log)
			s := string(requests)
			for _, asset := range []string{"SHA256SUMS", "nodekit-v0.2.0-linux-" + tc.asset + ".tar.gz"} {
				if !strings.Contains(s, "https://github.com/sample/nodekit/releases/download/v0.2.0/"+asset) {
					t.Fatal("asset not pinned to same release", s)
				}
			}
			if strings.Contains(s, "/releases/latest") != (tc.version == "") {
				t.Fatal("incorrect latest lookup", s)
			}
		})
	}
}

func TestGitHubInstallerRejectsUnattendedAndUnsafeInputs(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--repo", "../bad", "--non-interactive"}, {"--repo", "good/repo", "--version", "../../bad", "--non-interactive"},
		{"--repo", "good/repo", "--file", "archive", "--non-interactive"},
	} {
		cmd := exec.Command("bash", append([]string{filepath.Join("..", "..", "install.sh")}, args...)...)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("accepted unsafe arguments %v: %s", args, out)
		}
	}
}

func TestGitHubInstallerRejectsUnsupportedArchitectureBeforeDownload(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "uname"), []byte("#!/bin/sh\necho mips\n"), 0700)
	os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/bin/sh\necho unexpected-download\nexit 42\n"), 0700)
	cmd := exec.Command("bash", "../../install.sh", "--repo", "sample/nodekit", "--non-interactive")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "Unsupported architecture") || strings.Contains(string(out), "unexpected-download") {
		t.Fatalf("unsupported architecture reached download: %v %s", err, out)
	}
}
