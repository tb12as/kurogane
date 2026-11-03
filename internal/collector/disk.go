package collector

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/hostfs"
)

// statfs is swapped in tests.
var statfs = syscall.Statfs

// skipFS lists pseudo, image and network filesystems (network ones can hang statfs).
var skipFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "pstore": true, "bpf": true, "debugfs": true, "tracefs": true, "configfs": true,
	"fusectl": true, "mqueue": true, "hugetlbfs": true, "autofs": true, "binfmt_misc": true, "overlay": true,
	"squashfs": true, "nsfs": true, "ramfs": true, "rpc_pipefs": true, "efivarfs": true, "selinuxfs": true,
	"iso9660": true, "nfs": true, "nfs4": true, "cifs": true, "smb3": true, "sshfs": true, "ceph": true,
	"glusterfs": true, "9p": true, "virtiofs": true, "devfs": true, "zram": true,
}

// diskCollector reports space per mount (statfs) and I/O per block device (/proc/diskstats).
type diskCollector struct {
	mounts []Mount
	mntL   *labels
	devL   *labels
	prev   map[string]*ioStat
	prevT  time.Time
	f      [][]byte
}

type ioStat struct {
	reads, rsect, rms, writes, wsect, wms, ioms uint64
	seen                                        bool
}

func newDisk() *diskCollector {
	return &diskCollector{mntL: newLabels("mount"), devL: newLabels("dev"), prev: map[string]*ioStat{}}
}

func (c *diskCollector) Collect(context.Context) ([]Sample, error) {
	out, err1 := c.space(nil)
	out, err2 := c.io(out)
	return out, errors.Join(err1, err2)
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

func (c *diskCollector) space(out []Sample) ([]Sample, error) {
	b, err := hostfs.Read("/proc/mounts")
	if err != nil {
		return out, err
	}
	mounts := make([]Mount, 0, len(c.mounts))
	seen := map[string]bool{}
	var errs []error
	for l := range bytes.Lines(b) {
		c.f = fields(l, c.f)
		if len(c.f) < 4 {
			continue
		}
		fst := string(c.f[2])
		if skipFS[fst] || strings.HasPrefix(fst, "fuse.") {
			continue
		}
		dev := string(c.f[0])
		if seen[dev] {
			continue // bind mount of a device already reported
		}
		path := unescapeMount(string(c.f[1]))
		var st syscall.Statfs_t
		if err := statfs(hostfs.P(path), &st); err != nil {
			errs = append(errs, err)
			continue
		}
		if st.Blocks == 0 {
			continue
		}
		seen[dev] = true
		bs := uint64(st.Bsize)
		total, free, avail := st.Blocks*bs, st.Bfree*bs, st.Bavail*bs
		used := sub(total, free)
		up := pct(float64(used), float64(used+avail)) // df semantics: reserved blocks excluded
		mounts = append(mounts, Mount{Path: path, Device: dev, FSType: fst, Opts: string(c.f[3]), Total: total,
			Used: used, UsedPct: up})
		lb := c.mntL.get(c.f[1])
		if path != string(c.f[1]) {
			lb = map[string]string{"mount": path}
		}
		out = addL(out, "disk.used_pct", lb, up)
		out = addL(out, "disk.used_bytes", lb, float64(used))
		out = addL(out, "disk.total_bytes", lb, float64(total))
		out = addL(out, "disk.free_bytes", lb, float64(avail))
		if st.Files > 0 {
			out = addL(out, "disk.inodes_used_pct", lb, pct(float64(sub(st.Files, st.Ffree)), float64(st.Files)))
		}
	}
	c.mounts = mounts
	return out, errors.Join(errs...)
}

func (c *diskCollector) io(out []Sample) ([]Sample, error) {
	b, err := hostfs.Read("/proc/diskstats")
	if err != nil {
		return out, err
	}
	// whole disks are listed in /sys/block; partitions would double count
	var blk map[string]bool
	if names, err := readDirNames(hostfs.P("/sys/block")); err == nil {
		blk = make(map[string]bool, len(names))
		for _, n := range names {
			blk[n] = true
		}
	}
	t := now()
	dt := t.Sub(c.prevT).Seconds()
	first := c.prevT.IsZero()
	c.prevT = t
	for l := range bytes.Lines(b) {
		c.f = fields(l, c.f)
		if len(c.f) < 14 {
			continue
		}
		f := c.f
		name := f[2]
		if bytes.HasPrefix(name, []byte("loop")) || bytes.HasPrefix(name, []byte("ram")) ||
			bytes.HasPrefix(name, []byte("zram")) || (blk != nil && !blk[string(name)]) {
			continue
		}
		cur := ioStat{reads: atou(f[3]), rsect: atou(f[5]), rms: atou(f[6]), writes: atou(f[7]), wsect: atou(f[9]),
			wms: atou(f[10]), ioms: atou(f[12]), seen: true}
		if cur.reads == 0 && cur.writes == 0 {
			continue
		}
		p := c.prev[string(name)]
		if p == nil {
			p = &ioStat{}
			c.prev[string(name)] = p
		}
		if !first && p.seen {
			lb := c.devL.get(name)
			ios := sub(cur.reads, p.reads) + sub(cur.writes, p.writes)
			await := 0.0
			if ios > 0 {
				await = float64(sub(cur.rms, p.rms)+sub(cur.wms, p.wms)) / float64(ios)
			}
			util := pct(float64(sub(cur.ioms, p.ioms)), dt*1000)
			if util > 100 {
				util = 100
			}
			out = addL(out, "diskio.read_bps", lb, rate(cur.rsect, p.rsect, dt)*512)
			out = addL(out, "diskio.write_bps", lb, rate(cur.wsect, p.wsect, dt)*512)
			out = addL(out, "diskio.read_iops", lb, rate(cur.reads, p.reads, dt))
			out = addL(out, "diskio.write_iops", lb, rate(cur.writes, p.writes, dt))
			out = addL(out, "diskio.await_ms", lb, await)
			out = addL(out, "diskio.util_pct", lb, util)
		}
		*p = cur
	}
	return out, nil
}

func readDirNames(p string) ([]string, error) {
	d, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.Readdirnames(-1)
}
