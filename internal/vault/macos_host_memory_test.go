package vault

import "testing"

func TestFormatSnapshotOSArchLinuxAndMacOS(t *testing.T) {
	linuxSnap := &ServerMonitorSnapshot{
		OS:     "Ubuntu 24.04.1 LTS",
		Kernel: "6.8.0-45-generic",
		Arch:   "x86_64",
	}
	if got := formatSnapshotOSArch(linuxSnap); got != "Ubuntu 24.04.1 LTS / Linux 6.8.0-45-generic / x86_64" {
		t.Fatalf("unexpected Linux OSArch: %q", got)
	}

	macSnap := &ServerMonitorSnapshot{
		OS:     "macOS 15.3.1 (24D70)",
		Kernel: "24.3.0",
		Arch:   "arm64",
	}
	if got := formatSnapshotOSArch(macSnap); got != "macOS 15.3.1 (24D70) / Darwin 24.3.0 / arm64" {
		t.Fatalf("unexpected macOS OSArch: %q", got)
	}

	darwinSnap := &ServerMonitorSnapshot{
		OS:     "Darwin",
		Kernel: "24.3.0",
		Arch:   "arm64",
	}
	if got := formatSnapshotOSArch(darwinSnap); got != "Darwin / Darwin 24.3.0 / arm64" {
		t.Fatalf("unexpected Darwin OSArch: %q", got)
	}
}
