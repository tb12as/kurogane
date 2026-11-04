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
	"github.com/tb12as/kurogane/internal/metricsdb"
)

var units = []string{"kurogane", "kurogane-server", "kurogane-vm"}

var unitFiles = []string{
	"/etc/systemd/system/kurogane.service",
	"/lib/systemd/system/kurogane.service",
	"/lib/systemd/system/kurogane-server.service",
	metricsdb.UnitPath,
}

// removeShortLink removes the krgn link next to the binary, only when it points at that binary.
func removeShortLink(bin string) {
	link := filepath.Join(filepath.Dir(bin), "krgn")
	t, err := os.Readlink(link)
	if err != nil {
		return
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(link), t)
	}
	if filepath.Clean(t) == filepath.Clean(bin) {
		if err := os.Remove(link); err != nil {
			fmt.Println(" ", err)
		}
	}
}

// safeDir refuses paths whose removal could take the host with it (e.g. data_dir: /var).
func safeDir(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	c := filepath.Clean(p)
	return c != "/" && strings.Count(c, "/") >= 2
}

// pkgManager returns the package tool that owns kurogane, or "".
func pkgManager() string {
	if out, err := exec.Command("dpkg-query", "-W", "-f=${Status}", "kurogane").Output(); err == nil &&
		strings.Contains(string(out), "install ok installed") {
		return "apt-get"
	}
	if exec.Command("rpm", "-q", "kurogane").Run() == nil {
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
		Short: "Stop Kurogane and remove its units and binary (--purge also deletes data, config and user)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return errors.New("run as root (sudo kurogane uninstall)")
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
				fmt.Printf("and remove the kurogane package with %s.\n", pm)
			} else {
				fmt.Println("and remove the systemd units and the kurogane binary.")
			}
			if purge {
				fmt.Println("--purge also deletes", strings.Join(dirs, ", "), "and the kurogane system user.")
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
				tryRun(pm, "remove", "-y", "kurogane")
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
					removeShortLink(bin)
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
					tryRun("userdel", "kurogane")
				}
			}
			fmt.Println("Kurogane removed. The sshd drop-in (sshd_config.d/99-kurogane.conf) and hardening " +
				"changes were left in place on purpose; review them before deleting.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "also delete data_dir, the config dir, VictoriaMetrics data and the system user")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	rootCmd.AddCommand(cmd)
}
