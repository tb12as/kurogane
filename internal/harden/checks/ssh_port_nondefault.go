package checks

func init() {
	register(func(e *Env) Check {
		c := sshEq(Meta{ID: "SSH-PORT-NONDEFAULT", Title: "SSH on a non-default port", Severity: Low,
			Rationale: "Moving SSH off port 22 removes most automated scan noise (it is not a security boundary).",
			Remediation: "Optionally set `Port <n>` via `serverkeeper ssh config set Port <n>` after opening the new " +
				"port in the firewall; ignore this check if port 22 is required."}, e, "port")
		c.m.AutoFix = FixReport
		c.eval = func(m map[string]string) (bool, string) {
			return m["port"] != "22", "port " + m["port"]
		}
		c.plan = nil
		return c
	})
}
