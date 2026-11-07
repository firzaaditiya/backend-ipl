package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/quarantine"
	bolt "go.etcd.io/bbolt"
)

var errTest = errors.New("permission denied")

func TestBaselineUpdateAllowed(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		qres    quarantine.Result
		allowed bool
	}{
		{"deleted", models.ActionDeleted, quarantine.Result{}, true},
		{"created quarantined", models.ActionCreated, quarantine.Result{Success: true}, true},
		{"modified quarantined", models.ActionModified, quarantine.Result{Success: true}, true},
		{"created failed", models.ActionCreated, quarantine.Result{Err: errTest}, false},
		{"modified skipped", models.ActionModified, quarantine.Result{SkipReason: "file no longer exists"}, false},
		{"unreadable never", models.ActionUnreadable, quarantine.Result{Success: true}, false},
		{"quarantine breach never", models.ActionQuarantineBreach, quarantine.Result{Success: true}, false},
		{"released never", models.ActionReleased, quarantine.Result{Success: true}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := baselineUpdateAllowed(tc.action, tc.qres); got != tc.allowed {
				t.Fatalf("baselineUpdateAllowed(%s) = %v, want %v", tc.action, got, tc.allowed)
			}
		})
	}
}

func TestEventFingerprintIncludesReason(t *testing.T) {
	a := models.AnomalyEvent{Action: models.ActionUnreadable, ScanErr: "permission denied"}
	b := models.AnomalyEvent{Action: models.ActionUnreadable, ScanErr: "symlink tidak dipindai"}

	if eventFingerprint(a) == eventFingerprint(b) {
		t.Fatal("fingerprint harus berubah saat alasan berbeda")
	}
}

func TestFilterActiveQuarantineSuppressesExpectedUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quarantined.php")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	baseline := map[string]models.FileRecord{
		path: {Path: path, Hash: "old", Size: info.Size(), ModTime: info.ModTime()},
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	results := filterActiveQuarantine(
		[]models.ScanResult{{Path: path, Err: os.ErrPermission}},
		baseline,
		map[string]bool{path: true},
	)

	if len(results) != 0 {
		t.Fatalf("file yang dikarantina seharusnya tidak dilaporkan, got %+v", results)
	}
	if _, ok := baseline[path]; ok {
		t.Fatal("baseline path yang dikarantina seharusnya tidak dibandingkan")
	}
}

func TestFilterActiveQuarantineKeepsChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changed.php")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	baseline := map[string]models.FileRecord{
		path: {Path: path, Hash: "old", Size: info.Size() + 10, ModTime: info.ModTime()},
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	results := filterActiveQuarantine(
		[]models.ScanResult{{Path: path, Err: os.ErrPermission}},
		baseline,
		map[string]bool{path: true},
	)

	if len(results) != 1 {
		t.Fatalf("file yang berubah setelah karantina harus tetap dilaporkan, got %+v", results)
	}
}

func TestDetectQuarantineBreaches(t *testing.T) {
	mkfile := func(t *testing.T, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "victim.php")
		if err := os.WriteFile(path, []byte("<?php // benign"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
		return path
	}
	baselineFor := func(path string) map[string]models.FileRecord {
		return map[string]models.FileRecord{
			path: {Path: path, Hash: "abc", Mode: 0o644},
		}
	}

	t.Run("still quarantined (000) is not a breach", func(t *testing.T) {
		path := mkfile(t, 0o000)
		got := detectQuarantineBreaches(baselineFor(path), map[string]bool{path: true}, nil,
			map[string]models.ScanResult{})
		if len(got) != 0 {
			t.Fatalf("expected no breach, got %+v", got)
		}
	})

	t.Run("owner restores 0644 with same hash is a breach", func(t *testing.T) {
		path := mkfile(t, 0o644)
		got := detectQuarantineBreaches(baselineFor(path), map[string]bool{path: true}, nil,
			map[string]models.ScanResult{path: {Path: path, Hash: "abc", Mode: 0o644}})
		if len(got) != 1 {
			t.Fatalf("expected 1 breach, got %+v", got)
		}
		ev := got[0]
		if ev.Action != models.ActionQuarantineBreach {
			t.Fatalf("action = %q, want QUARANTINE_BREACH", ev.Action)
		}
		if ev.OldMode != 0 || ev.NewMode != 0o644 {
			t.Fatalf("modes = %04o -> %04o, want 0000 -> 0644", ev.OldMode, ev.NewMode)
		}
		if ev.OldHash != "abc" || ev.NewHash != "abc" {
			t.Fatalf("hashes = %q -> %q, want abc -> abc", ev.OldHash, ev.NewHash)
		}
	})

	t.Run("path with a compare event is skipped", func(t *testing.T) {
		path := mkfile(t, 0o644)
		got := detectQuarantineBreaches(baselineFor(path), map[string]bool{path: true},
			map[string]bool{path: true},
			map[string]models.ScanResult{path: {Path: path, Hash: "abc", Mode: 0o644}})
		if len(got) != 0 {
			t.Fatalf("expected no breach (already has an event), got %+v", got)
		}
	})

	t.Run("deleted file is not a breach", func(t *testing.T) {
		path := mkfile(t, 0o644)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		got := detectQuarantineBreaches(baselineFor(path), map[string]bool{path: true}, nil,
			map[string]models.ScanResult{})
		if len(got) != 0 {
			t.Fatalf("expected no breach for a deleted file, got %+v", got)
		}
	})

	t.Run("write-only mode (0200) still counts as quarantined", func(t *testing.T) {
		path := mkfile(t, 0o200)
		got := detectQuarantineBreaches(baselineFor(path), map[string]bool{path: true}, nil,
			map[string]models.ScanResult{})
		if len(got) != 0 {
			t.Fatalf("expected no breach for 0200 (unreadable, unexecutable), got %+v", got)
		}
	})

	t.Run("symlink replacing the file is a breach", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.php")
		if err := os.WriteFile(target, []byte("<?php // benign"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "victim.php")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		got := detectQuarantineBreaches(baselineFor(link), map[string]bool{link: true}, nil,
			map[string]models.ScanResult{})
		if len(got) != 1 {
			t.Fatalf("expected 1 breach for a symlink swap, got %+v", got)
		}
		if got[0].NewMode != 0o777 {
			t.Fatalf("NewMode = %04o, want 0777 (symlink perm bits)", got[0].NewMode)
		}
		if got[0].NewHash != "" {
			t.Fatalf("NewHash = %q, want empty (symlink is never hashed)", got[0].NewHash)
		}
	})

	t.Run("no quarantined files means no breaches", func(t *testing.T) {
		if got := detectQuarantineBreaches(nil, nil, nil, nil); len(got) != 0 {
			t.Fatalf("expected nil, got %+v", got)
		}
	})
}
func TestRunVerificationRecordsAndAlertsOnFailure(t *testing.T) {
	// Rantai utuh: hasil dicatat, tidak ada alert.
	dir := t.TempDir()
	path := filepath.Join(dir, "verify.db")
	db, err := ledger.New(path)
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	if _, err := db.AppendBlock(models.AnomalyEvent{FilePath: "/var/www/a.php", Action: models.ActionCreated, NewHash: "aaa"}); err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}
	jobs := make(chan alertJob, 4)
	lv := runVerification(db, jobs)
	if !lv.ChainValid || lv.TotalBlocks != 1 || lv.HeadBlockID != "BLK-000001" {
		t.Fatalf("runVerification on a valid chain = %+v", lv)
	}
	if len(jobs) != 0 {
		t.Fatalf("valid chain must not enqueue an alert, got %d job(s)", len(jobs))
	}
	got, err := db.GetLastVerification()
	if err != nil || got == nil || !got.ChainValid || got.HeadBlockID != "BLK-000001" {
		t.Fatalf("GetLastVerification = %+v, %v", got, err)
	}
	db.Close()

	// Rantai dirusak: buka file Bbolt langsung (ledger sudah ditutup),
	// ubah satu blok tanpa memperbarui hash-nya, lalu buka lagi lewat
	// ledger dan jalankan verifikasi.
	raw, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	err = raw.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		k, v := b.Cursor().First()
		var block models.Block
		if err := json.Unmarshal(v, &block); err != nil {
			return err
		}
		block.FilePath = "/var/www/backdoor.php"
		data, _ := json.Marshal(block)
		return b.Put(k, data)
	})
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}
	raw.Close()

	db2, err := ledger.New(path)
	if err != nil {
		t.Fatalf("ledger.New (reopen): %v", err)
	}
	defer db2.Close()
	lv = runVerification(db2, jobs)
	if lv.ChainValid {
		t.Fatal("runVerification must report an invalid chain")
	}
	if len(jobs) != 1 {
		t.Fatalf("invalid chain must enqueue exactly 1 alert, got %d", len(jobs))
	}
	job := <-jobs
	if job.kind != "system" || job.title != "RANTAI LEDGER RUSAK" {
		t.Fatalf("alert job = %+v, want system/RANTAI LEDGER RUSAK", job)
	}
	if !strings.Contains(job.message, "BLK-000001") {
		t.Fatalf("failure alert must name the failed block: %q", job.message)
	}
	got, err = db2.GetLastVerification()
	if err != nil || got == nil || got.ChainValid {
		t.Fatalf("GetLastVerification after failure = %+v, %v", got, err)
	}
}
