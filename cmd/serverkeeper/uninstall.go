package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tb12as/serverman/internal/metricsdb"
)

var units = []string{"serverkeeper", "serverkeeper-server", "serverkeeper-vm"}

var unitFiles = []string{
	"/etc/systemd/system/serverkeeper.service",
	"/lib/systemd/system/serverkeeper.service",
	"/lib/systemd/system/serverkeeper-server.service",
	metricsdb.UnitPath,
}

// safeDir refuses paths whose removal could take the host with it (e.g. data_dir: /var).
func safeDir(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	c := filepath.Clean(p)
	return c != "/" && strings.Count(c, "/") >= 2
}

// pkgManager returns the package tool that owns serverkeeper, or "".
func pkgManager() string {
	if out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", "serverkeeper").Output(); err == nil &&
		strings.Contains(string(out), "install ok installed") {
		return "apt-get"
	}
	if exec.Command("rpm", "-q", "serverkeeper").Run() == nil {
		return "dnf"
	}
	return ""
}

func tryRun(name string, args ...string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		fmt.Printf("  %s %s: %v %s\n", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func init() {
	var purge, yes bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop ServerKeeper and remove its units and binary (--purge also deletes data, config and user)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return errors.New("run as root (sudo serverkeeper uninstall)")
			}
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			dirs := []string{cfg.DataDir, filepath.Dir(flagConfig)}
			if vm := cfg.Server.VM.DataDir; vm != "" {
				dirs = append(dirs, vm)
			}
			for _, d := range dirs {
				if purge && !safeDir(d) {
					return fmt.Errorf("refusing to delete %q: fix data_dir/server.vm.data_dir in %s", d, flagConfig)
				}
			}
			pm := pkgManager()

			fmt.Println("This will stop and disable", strings.Join(units, ", "))
			if pm != "" {
				fmt.Printf("and remove the serverkeeper package with %s.\n", pm)
			} else {
				fmt.Println("and remove the systemd units and the serverkeeper binary.")
			}
			if purge {
				fmt.Println("--purge also deletes", strings.Join(dirs, ", "), "and the serverkeeper system user.")
			} else {
				fmt.Println("Data and config are kept:", strings.Join(dirs, ", "))
			}
			if !yes {
				fmt.Print("Continue? (y/N): ")
				s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(s)) != "y" {
					return errors.New("aborted")
				}
			}

			tryRun("systemctl", append([]string{"disable", "--now"}, units...)...)
			if pm != "" {
				tryRun(pm, "remove", "-y", "serverkeeper")
			} else {
				for _, f := range unitFiles {
					if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
						fmt.Println(" ", err)
					}
				}
				if bin, err := os.Executable(); err == nil {
					if err := os.Remove(bin); err != nil {
						fmt.Println(" ", err)
					}
				}
			}
			tryRun("systemctl", "daemon-reload")

			if purge {
				for _, d := range dirs {
					if err := os.RemoveAll(d); err != nil {
						fmt.Println(" ", err)
					}
				}
				if _, err := exec.LookPath("userdel"); err == nil {
					tryRun("userdel", "serverkeeper")
				}
			}
			fmt.Println("ServerKeeper removed. The sshd drop-in (sshd_config.d/99-serverkeeper.conf) and hardening " +
				"changes were left in place on purpose; review them before deleting.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "also delete data_dir, the config dir, VictoriaMetrics data and the system user")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	rootCmd.AddCommand(cmd)
}
