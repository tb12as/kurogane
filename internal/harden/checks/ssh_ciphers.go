package checks

import (
	"strings"
)

// recommended algorithm lists, used only when filtering the current list would leave nothing.
var sshStrong = map[string]string{
	"ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr," +
		"aes192-ctr,aes128-ctr",
	"macs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com," +
		"hmac-sha2-512,hmac-sha2-256",
	"kexalgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512," +
		"diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256",
}

// weakAlg reports CBC/3DES/arcfour ciphers, SHA1/MD5/64-bit MACs and SHA1 (incl. group1) key exchange.
func weakAlg(kind, a string) bool {
	a = strings.ToLower(a)
	switch kind {
	case "ciphers":
		return strings.Contains(a, "cbc") || strings.Contains(a, "3des") || strings.Contains(a, "arcfour") ||
			strings.Contains(a, "blowfish") || strings.Contains(a, "cast128")
	case "macs":
		return strings.Contains(a, "sha1") || strings.Contains(a, "md5") || strings.Contains(a, "-96") ||
			strings.Contains(a, "umac-64") || strings.Contains(a, "ripemd")
	}
	return strings.Contains(a, "sha1") || strings.Contains(a, "group1-")
}

func init() {
	register(func(e *Env) Check {
		c := sshEq(Meta{ID: "SSH-CIPHERS", Title: "SSH uses modern ciphers, MACs and key exchange", Severity: Medium,
			CIS:       "5.2.13",
			Rationale: "CBC ciphers, SHA1/MD5 MACs and SHA1 or group1 key exchange have known weaknesses.",
			Remediation: "Remove weak algorithms from Ciphers, MACs and KexAlgorithms in sshd_config " +
				"(`kurogane harden fix SSH-CIPHERS` keeps only the strong ones you already offer)."}, e, "ciphers")
		c.eval = func(m map[string]string) (bool, string) {
			var weak []string
			for _, k := range []string{"ciphers", "macs", "kexalgorithms"} {
				for _, a := range strings.Split(m[k], ",") {
					if weakAlg(k, a) {
						weak = append(weak, a)
					}
				}
			}
			if len(weak) == 0 {
				return true, "no weak ciphers, MACs or key exchange algorithms offered"
			}
			return false, "weak algorithms offered: " + strings.Join(weak, ", ")
		}
		c.plan = func(m map[string]string) map[string]string {
			set := map[string]string{}
			for _, k := range []string{"ciphers", "macs", "kexalgorithms"} {
				var keep []string
				for _, a := range strings.Split(m[k], ",") {
					if a != "" && !weakAlg(k, a) {
						keep = append(keep, a)
					}
				}
				if len(keep) == 0 {
					keep = []string{sshStrong[k]}
				}
				set[sshName(k)] = strings.Join(keep, ",")
			}
			return set
		}
		return c
	})
}
