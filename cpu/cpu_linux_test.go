package cpu

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestTimesEmpty(t *testing.T) {
	orig := os.Getenv("HOST_PROC")
	os.Setenv("HOST_PROC", "testdata/linux/times_empty")
	_, err := Times(true)
	if err != nil {
		t.Error("Times(true) failed")
	}
	_, err = Times(false)
	if err != nil {
		t.Error("Times(false) failed")
	}
	os.Setenv("HOST_PROC", orig)
}

func TestCPUparseStatLine_424(t *testing.T) {
	orig := os.Getenv("HOST_PROC")
	os.Setenv("HOST_PROC", "testdata/linux/424/proc")
	{
		l, err := Times(true)
		if err != nil || len(l) == 0 {
			t.Error("Times(true) failed")
		}
		t.Logf("Times(true): %#v", l)
	}
	{
		l, err := Times(false)
		if err != nil || len(l) == 0 {
			t.Error("Times(false) failed")
		}
		t.Logf("Times(false): %#v", l)
	}
	os.Setenv("HOST_PROC", orig)
}

func TestCPUCountsAgainstLscpu(t *testing.T) {
	lscpu, err := exec.LookPath("lscpu")
	if err != nil {
		t.Skip("no lscpu to compare with")
	}
	cmd := exec.Command(lscpu)
	cmd.Env = []string{"LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("error executing lscpu: %v", err)
	}
	var threadsPerCore, coresPerSocket, sockets int
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Thread(s) per core":
			threadsPerCore, _ = strconv.Atoi(strings.TrimSpace(fields[1]))
		case "Core(s) per socket":
			coresPerSocket, _ = strconv.Atoi(strings.TrimSpace(fields[1]))
		case "Socket(s)":
			sockets, _ = strconv.Atoi(strings.TrimSpace(fields[1]))
		}
	}
	if threadsPerCore == 0 || coresPerSocket == 0 || sockets == 0 {
		t.Errorf("missing info from lscpu: threadsPerCore=%d coresPerSocket=%d sockets=%d", threadsPerCore, coresPerSocket, sockets)
	}
	expectedPhysical := coresPerSocket * sockets
	expectedLogical := expectedPhysical * threadsPerCore
	physical, err := Counts(false)
	skipIfNotImplementedErr(t, err)
	if err != nil {
		t.Errorf("error %v", err)
	}
	logical, err := Counts(true)
	skipIfNotImplementedErr(t, err)
	if err != nil {
		t.Errorf("error %v", err)
	}
	if expectedPhysical != physical {
		t.Errorf("expected %v, got %v", expectedPhysical, physical)
	}
	if expectedLogical != logical {
		t.Errorf("expected %v, got %v", expectedLogical, logical)
	}
}

// generate testdata dirs with the following
// # on the host to be mocked
// TMP=$(mktemp -d); for I in $(ls -1 /proc/cpuinfo /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq /sys/devices/system/cpu/cpu*/topology/core_id); do mkdir -p "$TMP/${I%/*}"; cp "$I" "$TMP/$I"; done; tar czvf rootfs.tar.gz "$TMP"; rm -rf "$TMP"
// # copy rootfs.tar.gz on the Go dev machine and extract it to a new testdata dir
// mkdir cpu/testdata/linux/cpuinfo/newtestcase
// cd cpu/testdata/linux/cpuinfo/newtestcase
// tar xzvf /tmp/rootfs.tar.gz --strip-component=2
var cpuInfoTests = []struct {
	mockedRootFS string
	stats        []InfoStat
}{
	{"intelcorei5", []InfoStat{{
		CPU:        0,
		VendorID:   "GenuineIntel",
		Family:     "6",
		Model:      "78",
		Stepping:   3,
		PhysicalID: "0",
		CoreID:     "0",
		Cores:      1,
		ModelName:  "Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz",
		Mhz:        3000,
		CacheSize:  3072,
		Flags:      []string{"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clflush", "dts", "acpi", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm", "pbe", "syscall", "nx", "pdpe1gb", "rdtscp", "lm", "constant_tsc", "art", "arch_perfmon", "pebs", "bts", "rep_good", "nopl", "xtopology", "nonstop_tsc", "aperfmperf", "pni", "pclmulqdq", "dtes64", "monitor", "ds_cpl", "vmx", "smx", "est", "tm2", "ssse3", "sdbg", "fma", "cx16", "xtpr", "pdcm", "pcid", "sse4_1", "sse4_2", "x2apic", "movbe", "popcnt", "tsc_deadline_timer", "aes", "xsave", "avx", "f16c", "rdrand", "lahf_lm", "abm", "3dnowprefetch", "epb", "invpcid_single", "ibrs", "ibpb", "stibp", "kaiser", "tpr_shadow", "vnmi", "flexpriority", "ept", "vpid", "fsgsbase", "tsc_adjust", "bmi1", "hle", "avx2", "smep", "bmi2", "erms", "invpcid", "rtm", "mpx", "rdseed", "adx", "smap", "clflushopt", "intel_pt", "xsaveopt", "xsavec", "xgetbv1", "xsaves", "dtherm", "ida", "arat", "pln", "pts", "hwp", "hwp_notify", "hwp_act_window", "hwp_epp"},
		Microcode:  "0xc2",
	}, {
		CPU:        1,
		VendorID:   "GenuineIntel",
		Family:     "6",
		Model:      "78",
		Stepping:   3,
		PhysicalID: "0",
		CoreID:     "1",
		Cores:      1,
		ModelName:  "Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz",
		Mhz:        3000,
		CacheSize:  3072,
		Flags:      []string{"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clflush", "dts", "acpi", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm", "pbe", "syscall", "nx", "pdpe1gb", "rdtscp", "lm", "constant_tsc", "art", "arch_perfmon", "pebs", "bts", "rep_good", "nopl", "xtopology", "nonstop_tsc", "aperfmperf", "pni", "pclmulqdq", "dtes64", "monitor", "ds_cpl", "vmx", "smx", "est", "tm2", "ssse3", "sdbg", "fma", "cx16", "xtpr", "pdcm", "pcid", "sse4_1", "sse4_2", "x2apic", "movbe", "popcnt", "tsc_deadline_timer", "aes", "xsave", "avx", "f16c", "rdrand", "lahf_lm", "abm", "3dnowprefetch", "epb", "invpcid_single", "ibrs", "ibpb", "stibp", "kaiser", "tpr_shadow", "vnmi", "flexpriority", "ept", "vpid", "fsgsbase", "tsc_adjust", "bmi1", "hle", "avx2", "smep", "bmi2", "erms", "invpcid", "rtm", "mpx", "rdseed", "adx", "smap", "clflushopt", "intel_pt", "xsaveopt", "xsavec", "xgetbv1", "xsaves", "dtherm", "ida", "arat", "pln", "pts", "hwp", "hwp_notify", "hwp_act_window", "hwp_epp"},
		Microcode:  "0xc2",
	}, {
		CPU:        2,
		VendorID:   "GenuineIntel",
		Family:     "6",
		Model:      "78",
		Stepping:   3,
		PhysicalID: "0",
		CoreID:     "0",
		Cores:      1,
		ModelName:  "Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz",
		Mhz:        3000,
		CacheSize:  3072,
		Flags:      []string{"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clflush", "dts", "acpi", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm", "pbe", "syscall", "nx", "pdpe1gb", "rdtscp", "lm", "constant_tsc", "art", "arch_perfmon", "pebs", "bts", "rep_good", "nopl", "xtopology", "nonstop_tsc", "aperfmperf", "pni", "pclmulqdq", "dtes64", "monitor", "ds_cpl", "vmx", "smx", "est", "tm2", "ssse3", "sdbg", "fma", "cx16", "xtpr", "pdcm", "pcid", "sse4_1", "sse4_2", "x2apic", "movbe", "popcnt", "tsc_deadline_timer", "aes", "xsave", "avx", "f16c", "rdrand", "lahf_lm", "abm", "3dnowprefetch", "epb", "invpcid_single", "ibrs", "ibpb", "stibp", "kaiser", "tpr_shadow", "vnmi", "flexpriority", "ept", "vpid", "fsgsbase", "tsc_adjust", "bmi1", "hle", "avx2", "smep", "bmi2", "erms", "invpcid", "rtm", "mpx", "rdseed", "adx", "smap", "clflushopt", "intel_pt", "xsaveopt", "xsavec", "xgetbv1", "xsaves", "dtherm", "ida", "arat", "pln", "pts", "hwp", "hwp_notify", "hwp_act_window", "hwp_epp"},
		Microcode:  "0xc2",
	}, {
		CPU:        3,
		VendorID:   "GenuineIntel",
		Family:     "6",
		Model:      "78",
		Stepping:   3,
		PhysicalID: "0",
		CoreID:     "1",
		Cores:      1,
		ModelName:  "Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz",
		Mhz:        3000,
		CacheSize:  3072,
		Flags:      []string{"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clflush", "dts", "acpi", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm", "pbe", "syscall", "nx", "pdpe1gb", "rdtscp", "lm", "constant_tsc", "art", "arch_perfmon", "pebs", "bts", "rep_good", "nopl", "xtopology", "nonstop_tsc", "aperfmperf", "pni", "pclmulqdq", "dtes64", "monitor", "ds_cpl", "vmx", "smx", "est", "tm2", "ssse3", "sdbg", "fma", "cx16", "xtpr", "pdcm", "pcid", "sse4_1", "sse4_2", "x2apic", "movbe", "popcnt", "tsc_deadline_timer", "aes", "xsave", "avx", "f16c", "rdrand", "lahf_lm", "abm", "3dnowprefetch", "epb", "invpcid_single", "ibrs", "ibpb", "stibp", "kaiser", "tpr_shadow", "vnmi", "flexpriority", "ept", "vpid", "fsgsbase", "tsc_adjust", "bmi1", "hle", "avx2", "smep", "bmi2", "erms", "invpcid", "rtm", "mpx", "rdseed", "adx", "smap", "clflushopt", "intel_pt", "xsaveopt", "xsavec", "xgetbv1", "xsaves", "dtherm", "ida", "arat", "pln", "pts", "hwp", "hwp_notify", "hwp_act_window", "hwp_epp"},
		Microcode:  "0xc2",
	}},
	},
	{"scalewayc1", []InfoStat{{
		CPU:        0,
		VendorID:   "",
		Family:     "",
		Model:      "Marvell Armada 375 (Device Tree)",
		Stepping:   0,
		PhysicalID: "",
		CoreID:     "0",
		Cores:      1,
		ModelName:  "ARMv7 Processor rev 1 (v7l)",
		Mhz:        0,
		CacheSize:  0,
		Flags:      []string{"half", "thumb", "fastmult", "vfp", "edsp", "thumbee", "neon", "vfpv3", "tls", "vfpd32"},
		Microcode:  "",
	}, {
		CPU:        1,
		VendorID:   "",
		Family:     "",
		Model:      "Marvell Armada 375 (Device Tree)",
		Stepping:   0,
		PhysicalID: "",
		CoreID:     "1",
		Cores:      1,
		ModelName:  "ARMv7 Processor rev 1 (v7l)",
		Mhz:        0,
		CacheSize:  0,
		Flags:      []string{"half", "thumb", "fastmult", "vfp", "edsp", "thumbee", "neon", "vfpv3", "tls", "vfpd32"},
		Microcode:  "",
	}},
	},
}

func TestCpuInfoLinux(t *testing.T) {
	origProc := os.Getenv("HOST_PROC")
	defer os.Setenv("HOST_PROC", origProc)
	origSys := os.Getenv("HOST_PROC")
	defer os.Setenv("HOST_SYS", origSys)

	for _, tt := range cpuInfoTests {
		t.Run(tt.mockedRootFS, func(t *testing.T) {
			os.Setenv("HOST_PROC", filepath.Join("testdata/linux/cpuinfo/", tt.mockedRootFS, "proc"))
			os.Setenv("HOST_SYS", filepath.Join("testdata/linux/cpuinfo/", tt.mockedRootFS, "sys"))

			stats, err := Info()
			skipIfNotImplementedErr(t, err)
			if err != nil {
				t.Errorf("error %v", err)
			}
			if !reflect.DeepEqual(stats, tt.stats) {
				t.Errorf("got: %+v\nwant: %+v", stats, tt.stats)
			}
		})
	}
}
