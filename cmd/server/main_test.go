package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/quarantine"
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
