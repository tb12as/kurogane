// Package store is the agent's embedded bbolt store: raw samples, 1-minute rollups,
// pending SSH changes and the alert delivery queue (PRD §9 storage design).
package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tb12as/serverman/internal/collector"
	bolt "go.etcd.io/bbolt"
)

var (
	bRaw    = []byte("raw")
	bRollup = []byte("rollup")
	bSeries = []byte("series")
)

// Store wraps bbolt.
type Store struct {
	db *bolt.DB
	rw sync.RWMutex // exclusive only while Compact swaps db; lock order is mu then rw

	mu     sync.Mutex
	ids    map[string]uint64
	keys   map[uint64]string
	minute int64 // current rollup minute (unix s)
	acc    map[uint64]*agg
}

type agg struct {
	sum, max float64
	n        int
}

var opts = &bolt.Options{Timeout: 5 * time.Second, NoFreelistSync: true}

// Open opens (or creates) the store at path with mode 0600.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, opts)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, ids: map[string]uint64{}, keys: map[uint64]string{}, acc: map[uint64]*agg{}}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bRaw, bRollup, bSeries} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return tx.Bucket(bSeries).ForEach(func(k, v []byte) error {
			id := binary.BigEndian.Uint64(v)
			s.ids[string(k)], s.keys[id] = id, string(k)
			return nil
		})
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rw.Lock()
	defer s.rw.Unlock()
	_ = s.flushRollup(0)
	return s.db.Close()
}

// DB exposes bbolt for tests and backups.
func (s *Store) DB() *bolt.DB {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.db
}

func tsKey(t int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(t))
	return b[:]
}

func (s *Store) seriesID(tx *bolt.Tx, key string) (uint64, error) {
	if id, ok := s.ids[key]; ok {
		return id, nil
	}
	b := tx.Bucket(bSeries)
	id, err := b.NextSequence()
	if err != nil {
		return 0, err
	}
	if err := b.Put([]byte(key), tsKey(int64(id))); err != nil {
		return 0, err
	}
	s.ids[key], s.keys[id] = id, key
	return id, nil
}

// Append stores one tick of samples (raw) and folds them into the 1-minute rollup.
func (s *Store) Append(ts time.Time, samples []collector.Sample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rw.RLock()
	defer s.rw.RUnlock()
	min := ts.Unix() / 60 * 60
	if s.minute != 0 && min != s.minute {
		if err := s.flushRollup(min); err != nil {
			return err
		}
	}
	if s.minute == 0 {
		s.minute = min
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		buf := binary.AppendUvarint(nil, uint64(len(samples)))
		for _, x := range samples {
			if math.IsNaN(x.Value) || math.IsInf(x.Value, 0) {
				continue
			}
			id, err := s.seriesID(tx, x.Key())
			if err != nil {
				return err
			}
			buf = binary.AppendUvarint(buf, id)
			buf = binary.BigEndian.AppendUint64(buf, math.Float64bits(x.Value))
			a := s.acc[id]
			if a == nil {
				a = &agg{max: math.Inf(-1)}
				s.acc[id] = a
			}
			a.sum += x.Value
			a.n++
			a.max = math.Max(a.max, x.Value)
		}
		return tx.Bucket(bRaw).Put(tsKey(ts.UnixMilli()), buf)
	})
}

// flushRollup writes the accumulated minute and starts next; callers hold mu and rw.
func (s *Store) flushRollup(next int64) error {
	if len(s.acc) == 0 || s.minute == 0 {
		s.minute = next
		return nil
	}
	buf := binary.AppendUvarint(nil, uint64(len(s.acc)))
	for id, a := range s.acc {
		buf = binary.AppendUvarint(buf, id)
		buf = binary.BigEndian.AppendUint64(buf, math.Float64bits(a.sum/float64(a.n)))
		buf = binary.BigEndian.AppendUint64(buf, math.Float64bits(a.max))
	}
	m := s.minute
	s.acc, s.minute = map[uint64]*agg{}, next
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bRollup).Put(tsKey(m*1000), buf) })
}

// Point is [unix ms, avg, max].
type Point [3]float64

// Series is one time series in a query result.
type Series struct {
	Metric string            `json:"metric"`
	Labels map[string]string `json:"labels,omitempty"`
	Points []Point           `json:"points"`
}

// Query selects series whose metric equals or starts with "name." for any name, between From and To.
type Query struct {
	Names []string
	From  time.Time
	To    time.Time
	Step  time.Duration
}

func match(metric string, names []string) bool {
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if metric == n || strings.HasPrefix(metric, n+".") {
			return true
		}
	}
	return false
}

// Query reads raw data when the window is within the raw retention and step < 1m, else rollups.
func (s *Store) Query(q Query, rawRetention time.Duration) ([]Series, error) {
	if q.To.IsZero() {
		q.To = time.Now()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-time.Hour)
	}
	if q.Step <= 0 {
		q.Step = autoStep(q.To.Sub(q.From))
	}
	useRaw := q.Step < time.Minute && time.Since(q.From) <= rawRetention
	bucket := bRollup
	if useRaw {
		bucket = bRaw
	}
	s.mu.Lock()
	keys := make(map[uint64]string, len(s.keys))
	for id, k := range s.keys {
		if m, _ := collector.ParseKey(k); match(m, q.Names) {
			keys[id] = k
		}
	}
	s.mu.Unlock()

	type bucketAgg struct {
		sum, max float64
		n        int
	}
	step := q.Step.Milliseconds()
	data := map[uint64]map[int64]*bucketAgg{}
	s.rw.RLock()
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		end := q.To.UnixMilli()
		for k, v := c.Seek(tsKey(q.From.UnixMilli())); k != nil && int64(binary.BigEndian.Uint64(k)) <= end; k, v = c.Next() {
			ts := int64(binary.BigEndian.Uint64(k))
			slot := ts / step * step
			n, off := binary.Uvarint(v)
			for i := uint64(0); i < n && off < len(v); i++ {
				id, l := binary.Uvarint(v[off:])
				off += l
				if off+8 > len(v) {
					break
				}
				val := math.Float64frombits(binary.BigEndian.Uint64(v[off:]))
				off += 8
				mx := val
				if !useRaw {
					mx = math.Float64frombits(binary.BigEndian.Uint64(v[off:]))
					off += 8
				}
				if _, ok := keys[id]; !ok {
					continue
				}
				m := data[id]
				if m == nil {
					m = map[int64]*bucketAgg{}
					data[id] = m
				}
				a := m[slot]
				if a == nil {
					a = &bucketAgg{max: math.Inf(-1)}
					m[slot] = a
				}
				a.sum += val
				a.n++
				a.max = math.Max(a.max, mx)
			}
		}
		return nil
	})
	s.rw.RUnlock()
	if err != nil {
		return nil, err
	}
	out := make([]Series, 0, len(data))
	for id, m := range data {
		metric, labels := collector.ParseKey(keys[id])
		sr := Series{Metric: metric, Labels: labels, Points: make([]Point, 0, len(m))}
		for ts, a := range m {
			sr.Points = append(sr.Points, Point{float64(ts), a.sum / float64(a.n), a.max})
		}
		sort.Slice(sr.Points, func(i, j int) bool { return sr.Points[i][0] < sr.Points[j][0] })
		out = append(out, sr)
	}
	sort.Slice(out, func(i, j int) bool {
		return collector.SeriesKey(out[i].Metric, out[i].Labels) < collector.SeriesKey(out[j].Metric, out[j].Labels)
	})
	return out, nil
}

// autoStep keeps responses around 360 points for the UI ranges 1h/6h/24h/7d.
func autoStep(d time.Duration) time.Duration {
	st := d / 360
	if st < 10*time.Second {
		return 10 * time.Second
	}
	return st.Truncate(time.Second)
}

// Prune deletes raw samples older than raw and rollups older than rollup.
func (s *Store) Prune(raw, rollup time.Duration) error {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, p := range []struct {
			b   []byte
			ret time.Duration
		}{{bRaw, raw}, {bRollup, rollup}} {
			cut := tsKey(time.Now().Add(-p.ret).UnixMilli())
			c := tx.Bucket(p.b).Cursor()
			for k, _ := c.First(); k != nil && string(k) < string(cut); k, _ = c.Next() {
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ---- generic JSON key/value buckets (pending SSH changes, alert queue, baselines) ----

var ErrNotFound = errors.New("store: not found")

func (s *Store) Put(bucket, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		bk, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return bk.Put([]byte(key), b)
	})
}

func (s *Store) Get(bucket, key string, v any) error {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket([]byte(bucket))
		if bk == nil {
			return ErrNotFound
		}
		b := bk.Get([]byte(key))
		if b == nil {
			return ErrNotFound
		}
		return json.Unmarshal(b, v)
	})
}

func (s *Store) Delete(bucket, key string) error {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket([]byte(bucket))
		if bk == nil {
			return nil
		}
		return bk.Delete([]byte(key))
	})
}

// List calls fn for each key/value in bucket in key order.
func (s *Store) List(bucket string, fn func(key string, raw []byte) error) error {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket([]byte(bucket))
		if bk == nil {
			return nil
		}
		return bk.ForEach(func(k, v []byte) error { return fn(string(k), v) })
	})
}

// Enqueue appends v to a FIFO bucket and returns its sequence key.
func (s *Store) Enqueue(bucket string, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var key string
	s.rw.RLock()
	defer s.rw.RUnlock()
	err = s.db.Update(func(tx *bolt.Tx) error {
		bk, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		seq, _ := bk.NextSequence()
		key = string(tsKey(int64(seq)))
		return bk.Put([]byte(key), b)
	})
	return key, err
}

// Size returns the on-disk size of the store in bytes.
func (s *Store) Size() int64 {
	s.rw.RLock()
	defer s.rw.RUnlock()
	var n int64
	_ = s.db.View(func(tx *bolt.Tx) error { n = tx.Size(); return nil })
	return n
}

// ClearHistory deletes raw samples and rollups older than d (0 = all, including the open minute).
func (s *Store) ClearHistory(d time.Duration) error {
	if d <= 0 {
		s.mu.Lock()
		s.acc, s.minute = map[uint64]*agg{}, 0
		s.mu.Unlock()
	}
	return s.Prune(d, d)
}

// Compact rewrites the file without free pages; bbolt never shrinks its file on delete.
// It returns the bytes given back to the filesystem.
func (s *Store) Compact() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rw.Lock()
	defer s.rw.Unlock()
	// the open rollup minute stays in memory (s.acc) and is flushed into the new file later

	p := s.db.Path()
	before := fileSize(p)
	tmp := p + ".compact"
	_ = os.Remove(tmp)
	dst, err := bolt.Open(tmp, 0o600, opts)
	if err != nil {
		return 0, err
	}
	if err := bolt.Compact(dst, s.db, 64<<20); err != nil {
		dst.Close()
		os.Remove(tmp)
		return 0, err
	}
	if err := dst.Close(); err != nil {
		os.Remove(tmp)
		return 0, err
	}

	if err := s.db.Close(); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	rerr := os.Rename(tmp, p)
	if rerr != nil {
		os.Remove(tmp)
	}
	// reopen either the compacted file or, if the rename failed, the untouched original
	if s.db, err = bolt.Open(p, 0o600, opts); err != nil {
		return 0, err
	}
	if rerr != nil {
		return 0, rerr
	}
	return before - fileSize(p), nil
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// BucketStat is the space one bucket uses.
type BucketStat struct {
	Name  string `json:"name"`
	Keys  int    `json:"keys"`
	Bytes int64  `json:"bytes"`
}

// Stats describes the store file for the storage page.
type Stats struct {
	FileBytes        int64        `json:"file_bytes"`
	ReclaimableBytes int64        `json:"reclaimable_bytes"`
	Buckets          []BucketStat `json:"buckets"`
	RawOldest        *time.Time   `json:"raw_oldest,omitempty"`
	RawNewest        *time.Time   `json:"raw_newest,omitempty"`
	RollupOldest     *time.Time   `json:"rollup_oldest,omitempty"`
	RollupNewest     *time.Time   `json:"rollup_newest,omitempty"`
}

func keyTime(k []byte) *time.Time {
	if len(k) != 8 {
		return nil
	}
	t := time.UnixMilli(int64(binary.BigEndian.Uint64(k))).UTC()
	return &t
}

// Stats reports per-bucket usage, free pages and the time range of the history.
func (s *Store) Stats() (Stats, error) {
	s.rw.RLock()
	defer s.rw.RUnlock()
	var st Stats
	err := s.db.View(func(tx *bolt.Tx) error {
		st.FileBytes = fileSize(s.db.Path())
		err := tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			bs := b.Stats()
			st.Buckets = append(st.Buckets, BucketStat{Name: string(name), Keys: bs.KeyN,
				Bytes: int64(bs.BranchInuse + bs.LeafInuse + bs.InlineBucketInuse)})
			return nil
		})
		if err != nil {
			return err
		}
		c := tx.Bucket(bRaw).Cursor()
		k, _ := c.First()
		st.RawOldest = keyTime(k)
		k, _ = c.Last()
		st.RawNewest = keyTime(k)
		c = tx.Bucket(bRollup).Cursor()
		k, _ = c.First()
		st.RollupOldest = keyTime(k)
		k, _ = c.Last()
		st.RollupNewest = keyTime(k)
		return nil
	})
	ds := s.db.Stats()
	st.ReclaimableBytes = int64(ds.FreePageN+ds.PendingPageN) * int64(s.db.Info().PageSize)
	return st, err
}
