// +build windows

package process

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	cpu "github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/internal/common"
	net "github.com/shirou/gopsutil/net"
	"github.com/shirou/w32"
	"golang.org/x/sys/windows"
)

const (
	NoMoreFiles   = 0x12
	MaxPathLength = 260

	errnoERROR_IO_PENDING = 997        // https://github.com/golang/go/blob/79f6c280b8c06de823f6c438e5b53052a95057bc/src/internal/syscall/windows/zsyscall_windows.go#L16
	SE_PRIVILEGE_ENABLED  = 0x00000002 // https://github.com/golang/go/blob/79f6c280b8c06de823f6c438e5b53052a95057bc/src/internal/syscall/windows/security_windows.go#L24
)

var (
	modadvapi32               = syscall.NewLazyDLL("advapi32.dll")
	modkernel32               = syscall.NewLazyDLL("kernel32.dll")
	modpsapi                  = windows.NewLazyDLL("psapi.dll")
	procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")
	procGetCurrentProcess     = modkernel32.NewProc("GetCurrentProcess")
	procGetCurrentThread      = modkernel32.NewProc("GetCurrentThread")
	procGetProcessMemoryInfo  = modpsapi.NewProc("GetProcessMemoryInfo")
	procLookupPrivilegeValueW = modadvapi32.NewProc("LookupPrivilegeValueW")
	procOpenProcessToken      = modadvapi32.NewProc("OpenProcessToken")
	procOpenThreadToken       = modadvapi32.NewProc("OpenThreadToken")

	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

type SystemProcessInformation struct {
	NextEntryOffset   uint64
	NumberOfThreads   uint64
	Reserved1         [48]byte
	Reserved2         [3]byte
	UniqueProcessID   uintptr
	Reserved3         uintptr
	HandleCount       uint64
	Reserved4         [4]byte
	Reserved5         [11]byte
	PeakPagefileUsage uint64
	PrivatePageCount  uint64
	Reserved6         [6]uint64
}

// Memory_info_ex is different between OSes
type MemoryInfoExStat struct {
}

type MemoryMapsStat struct {
}

type Win32_Process struct {
	Name                  string
	ExecutablePath        *string
	CommandLine           *string
	Priority              uint32
	CreationDate          *time.Time
	ProcessID             uint32
	ThreadCount           uint32
	Status                *string
	ReadOperationCount    uint64
	ReadTransferCount     uint64
	WriteOperationCount   uint64
	WriteTransferCount    uint64
	CSCreationClassName   string
	CSName                string
	Caption               *string
	CreationClassName     string
	Description           *string
	ExecutionState        *uint16
	HandleCount           uint32
	KernelModeTime        uint64
	MaximumWorkingSetSize *uint32
	MinimumWorkingSetSize *uint32
	OSCreationClassName   string
	OSName                string
	OtherOperationCount   uint64
	OtherTransferCount    uint64
	PageFaults            uint32
	PageFileUsage         uint32
	ParentProcessID       uint32
	PeakPageFileUsage     uint32
	PeakVirtualSize       uint64
	PeakWorkingSetSize    uint32
	PrivatePageCount      uint64
	TerminationDate       *time.Time
	UserModeTime          uint64
	WorkingSetSize        uint64
}

func init() {
	wmi.DefaultClient.AllowMissingFields = true
}

func Pids() ([]int32, error) {
	// inspired by https://gist.github.com/henkman/3083408
	// and https://github.com/giampaolo/psutil/blob/1c3a15f637521ba5c0031283da39c733fda53e4c/psutil/arch/windows/process_info.c#L315-L329
	var ret []int32
	var read uint32 = 0
	var psSize uint32 = 1024
	const dwordSize uint32 = 4

	for {
		ps := make([]uint32, psSize)
		if !w32.EnumProcesses(ps, uint32(len(ps)), &read) {
			return nil, fmt.Errorf("could not get w32.EnumProcesses")
		}
		if uint32(len(ps)) == read { // ps buffer was too small to host every results, retry with a bigger one
			psSize += 1024
			continue
		}
		for _, pid := range ps[:read/dwordSize] {
			ret = append(ret, int32(pid))
		}
		return ret, nil

	}

}

func (p *Process) Ppid() (int32, error) {
	ppid, _, _, err := getFromSnapProcess(p.Pid)
	if err != nil {
		return 0, err
	}
	return ppid, nil
}

func GetWin32Proc(pid int32) ([]Win32_Process, error) {
	var dst []Win32_Process
	query := fmt.Sprintf("WHERE ProcessId = %d", pid)
	q := wmi.CreateQuery(&dst, query)
	ctx, cancel := context.WithTimeout(context.Background(), common.Timeout)
	defer cancel()
	err := common.WMIQueryWithContext(ctx, q, &dst)
	if err != nil {
		return []Win32_Process{}, fmt.Errorf("could not get win32Proc: %s", err)
	}

	if len(dst) == 0 {
		return []Win32_Process{}, fmt.Errorf("could not get win32Proc: empty")
	}

	return dst, nil
}

func (p *Process) Name() (string, error) {
	_, _, name, err := getFromSnapProcess(p.Pid)
	if err != nil {
		return "", fmt.Errorf("could not get Name: %s", err)
	}
	return name, nil
}

func (p *Process) Exe() (string, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return "", fmt.Errorf("could not get ExecutablePath: %s", err)
	}
	return *dst[0].ExecutablePath, nil
}

func (p *Process) Cmdline() (string, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return "", fmt.Errorf("could not get CommandLine: %s", err)
	}
	return *dst[0].CommandLine, nil
}

// CmdlineSlice returns the command line arguments of the process as a slice with each
// element being an argument. This merely returns the CommandLine informations passed
// to the process split on the 0x20 ASCII character.
func (p *Process) CmdlineSlice() ([]string, error) {
	cmdline, err := p.Cmdline()
	if err != nil {
		return nil, err
	}
	return strings.Split(cmdline, " "), nil
}

func (p *Process) CreateTime() (int64, error) {
	ru, err := getRusage(p.Pid)
	if err != nil {
		return 0, fmt.Errorf("could not get CreationDate: %s", err)
	}

	return ru.CreationTime.Nanoseconds() / 1000000, nil
}

func (p *Process) Cwd() (string, error) {
	return "", common.ErrNotImplementedError
}
func (p *Process) Parent() (*Process, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return nil, fmt.Errorf("could not get ParentProcessID: %s", err)
	}

	return NewProcess(int32(dst[0].ParentProcessID))
}
func (p *Process) Status() (string, error) {
	return "", common.ErrNotImplementedError
}
func (p *Process) Username() (string, error) {
	pid := p.Pid
	// 0x1000 is PROCESS_QUERY_LIMITED_INFORMATION
	c, err := syscall.OpenProcess(0x1000, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(c)

	var token syscall.Token
	err = syscall.OpenProcessToken(c, syscall.TOKEN_QUERY, &token)
	if err != nil {
		return "", err
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()

	user, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	return domain + "\\" + user, err
}

func (p *Process) Uids() ([]int32, error) {
	var uids []int32

	return uids, common.ErrNotImplementedError
}
func (p *Process) Gids() ([]int32, error) {
	var gids []int32
	return gids, common.ErrNotImplementedError
}
func (p *Process) Terminal() (string, error) {
	return "", common.ErrNotImplementedError
}

// Nice returnes priority in Windows
func (p *Process) Nice() (int32, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return 0, fmt.Errorf("could not get Priority: %s", err)
	}
	return int32(dst[0].Priority), nil
}
func (p *Process) IOnice() (int32, error) {
	return 0, common.ErrNotImplementedError
}
func (p *Process) Rlimit() ([]RlimitStat, error) {
	var rlimit []RlimitStat

	return rlimit, common.ErrNotImplementedError
}
func (p *Process) RlimitUsage(_ bool) ([]RlimitStat, error) {
	var rlimit []RlimitStat

	return rlimit, common.ErrNotImplementedError
}

func (p *Process) IOCounters() (*IOCountersStat, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil || len(dst) == 0 {
		return nil, fmt.Errorf("could not get Win32Proc: %s", err)
	}
	ret := &IOCountersStat{
		ReadCount:  uint64(dst[0].ReadOperationCount),
		ReadBytes:  uint64(dst[0].ReadTransferCount),
		WriteCount: uint64(dst[0].WriteOperationCount),
		WriteBytes: uint64(dst[0].WriteTransferCount),
	}

	return ret, nil
}
func (p *Process) NumCtxSwitches() (*NumCtxSwitchesStat, error) {
	return nil, common.ErrNotImplementedError
}
func (p *Process) NumFDs() (int32, error) {
	return 0, common.ErrNotImplementedError
}
func (p *Process) NumThreads() (int32, error) {
	dst, err := GetWin32Proc(p.Pid)
	if err != nil {
		return 0, fmt.Errorf("could not get ThreadCount: %s", err)
	}
	return int32(dst[0].ThreadCount), nil
}
func (p *Process) Threads() (map[int32]*cpu.TimesStat, error) {
	ret := make(map[int32]*cpu.TimesStat)
	return ret, common.ErrNotImplementedError
}
func (p *Process) Times() (*cpu.TimesStat, error) {
	sysTimes, err := getProcessCPUTimes(p.Pid)
	if err != nil {
		return nil, err
	}

	// User and kernel times are represented as a FILETIME structure
	// wich contains a 64-bit value representing the number of
	// 100-nanosecond intervals since January 1, 1601 (UTC):
	// http://msdn.microsoft.com/en-us/library/ms724284(VS.85).aspx
	// To convert it into a float representing the seconds that the
	// process has executed in user/kernel mode I borrowed the code
	// below from psutil's _psutil_windows.c, and in turn from Python's
	// Modules/posixmodule.c

	user := float64(sysTimes.UserTime.HighDateTime)*429.4967296 + float64(sysTimes.UserTime.LowDateTime)*1e-7
	kernel := float64(sysTimes.KernelTime.HighDateTime)*429.4967296 + float64(sysTimes.KernelTime.LowDateTime)*1e-7

	return &cpu.TimesStat{
		User:   user,
		System: kernel,
	}, nil
}
func (p *Process) CPUAffinity() ([]int32, error) {
	return nil, common.ErrNotImplementedError
}
func (p *Process) MemoryInfo() (*MemoryInfoStat, error) {
	mem, err := getMemoryInfo(p.Pid)
	if err != nil {
		return nil, err
	}

	ret := &MemoryInfoStat{
		RSS: uint64(mem.WorkingSetSize),
		VMS: uint64(mem.PagefileUsage),
	}

	return ret, nil
}
func (p *Process) MemoryInfoEx() (*MemoryInfoExStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Children() ([]*Process, error) {
	var dst []Win32_Process
	query := wmi.CreateQuery(&dst, fmt.Sprintf("Where ParentProcessId = %d", p.Pid))
	ctx, cancel := context.WithTimeout(context.Background(), common.Timeout)
	defer cancel()
	err := common.WMIQueryWithContext(ctx, query, &dst)
	if err != nil {
		return nil, err
	}

	out := []*Process{}
	for _, proc := range dst {
		p, err := NewProcess(int32(proc.ProcessID))
		if err != nil {
			continue
		}
		out = append(out, p)
	}

	return out, nil
}

func (p *Process) OpenFiles() ([]OpenFilesStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) Connections() ([]net.ConnectionStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) NetIOCounters(pernic bool) ([]net.IOCountersStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) IsRunning() (bool, error) {
	return true, common.ErrNotImplementedError
}

func (p *Process) MemoryMaps(grouped bool) (*[]MemoryMapsStat, error) {
	var ret []MemoryMapsStat
	return &ret, common.ErrNotImplementedError
}

func NewProcess(pid int32) (*Process, error) {
	p := &Process{Pid: pid}

	return p, nil
}

func (p *Process) SendSignal(sig windows.Signal) error {
	return common.ErrNotImplementedError
}

func (p *Process) Suspend() error {
	return common.ErrNotImplementedError
}
func (p *Process) Resume() error {
	return common.ErrNotImplementedError
}

func (p *Process) Terminate() error {
	// PROCESS_TERMINATE = 0x0001
	proc := w32.OpenProcess(0x0001, false, uint32(p.Pid))
	ret := w32.TerminateProcess(proc, 0)
	w32.CloseHandle(proc)

	if ret == false {
		return windows.GetLastError()
	} else {
		return nil
	}
}

func (p *Process) Kill() error {
	return common.ErrNotImplementedError
}

func getFromSnapProcess(pid int32) (int32, int32, string, error) {
	snap := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPPROCESS, uint32(pid))
	if snap == 0 {
		return 0, 0, "", windows.GetLastError()
	}
	defer w32.CloseHandle(snap)
	var pe32 w32.PROCESSENTRY32
	pe32.DwSize = uint32(unsafe.Sizeof(pe32))
	if w32.Process32First(snap, &pe32) == false {
		return 0, 0, "", windows.GetLastError()
	}

	if pe32.Th32ProcessID == uint32(pid) {
		szexe := windows.UTF16ToString(pe32.SzExeFile[:])
		return int32(pe32.Th32ParentProcessID), int32(pe32.CntThreads), szexe, nil
	}

	for w32.Process32Next(snap, &pe32) {
		if pe32.Th32ProcessID == uint32(pid) {
			szexe := windows.UTF16ToString(pe32.SzExeFile[:])
			return int32(pe32.Th32ParentProcessID), int32(pe32.CntThreads), szexe, nil
		}
	}
	return 0, 0, "", fmt.Errorf("Couldn't find pid: %d", pid)
}

// Get processes
func Processes() ([]*Process, error) {
	pids, err := Pids()
	if err != nil {
		return []*Process{}, fmt.Errorf("could not get Processes %s", err)
	}

	results := []*Process{}
	for _, pid := range pids {
		p, err := NewProcess(int32(pid))
		if err != nil {
			continue
		}
		results = append(results, p)
	}

	return results, nil
}

func getProcInfo(pid int32) (*SystemProcessInformation, error) {
	initialBufferSize := uint64(0x4000)
	bufferSize := initialBufferSize
	buffer := make([]byte, bufferSize)

	var sysProcInfo SystemProcessInformation
	ret, _, _ := common.ProcNtQuerySystemInformation.Call(
		uintptr(unsafe.Pointer(&sysProcInfo)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		uintptr(unsafe.Pointer(&bufferSize)))
	if ret != 0 {
		return nil, windows.GetLastError()
	}

	return &sysProcInfo, nil
}

func getRusage(pid int32) (*windows.Rusage, error) {
	var CPU windows.Rusage

	err := enableSeDebugPrivilege()
	if err != nil {
		return nil, err
	}

	c, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(c)

	if err := windows.GetProcessTimes(c, &CPU.CreationTime, &CPU.ExitTime, &CPU.KernelTime, &CPU.UserTime); err != nil {
		return nil, err
	}

	return &CPU, nil
}

func getMemoryInfo(pid int32) (PROCESS_MEMORY_COUNTERS, error) {
	var mem PROCESS_MEMORY_COUNTERS
	// PROCESS_QUERY_LIMITED_INFORMATION is 0x1000
	c, err := windows.OpenProcess(0x1000, false, uint32(pid))
	if err != nil {
		return mem, err
	}
	defer windows.CloseHandle(c)
	if err := getProcessMemoryInfo(c, &mem); err != nil {
		return mem, err
	}

	return mem, err
}

func getProcessMemoryInfo(h windows.Handle, mem *PROCESS_MEMORY_COUNTERS) (err error) {
	r1, _, e1 := syscall.Syscall(procGetProcessMemoryInfo.Addr(), 3, uintptr(h), uintptr(unsafe.Pointer(mem)), uintptr(unsafe.Sizeof(*mem)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

type SYSTEM_TIMES struct {
	CreateTime syscall.Filetime
	ExitTime   syscall.Filetime
	KernelTime syscall.Filetime
	UserTime   syscall.Filetime
}

func getProcessCPUTimes(pid int32) (SYSTEM_TIMES, error) {
	var times SYSTEM_TIMES

	// PROCESS_QUERY_LIMITED_INFORMATION is 0x1000
	h, err := windows.OpenProcess(0x1000, false, uint32(pid))
	if err != nil {
		return times, err
	}
	defer windows.CloseHandle(h)

	err = syscall.GetProcessTimes(
		syscall.Handle(h),
		&times.CreateTime,
		&times.ExitTime,
		&times.KernelTime,
		&times.UserTime,
	)

	return times, err
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

func errnoErr(e syscall.Errno) error { // https://golang.org/src/syscall/zsyscall_windows.go#L24
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

func getCurrentProcess() (pseudoHandle Handle, err error) { // https://golang.org/src/syscall/zsyscall_windows.go#L674
	r0, _, e1 := syscall.Syscall(procGetCurrentProcess.Addr(), 0, 0, 0, 0)
	pseudoHandle = Handle(r0)
	if pseudoHandle == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func openProcessToken(h Handle, access uint32, token *syscall.Token) (err error) { // https://golang.org/src/syscall/zsyscall_windows.go#L1865
	r1, _, e1 := syscall.Syscall(procOpenProcessToken.Addr(), 3, uintptr(h), uintptr(access), uintptr(unsafe.Pointer(token)))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func lookupPrivilegeValue(systemname *uint16, name *uint16, luid *LUID) (err error) { // https://github.com/golang/go/blob/9c64c65d0ea251c3ac4d49556f10ad6ceb532f52/src/internal/syscall/windows/zsyscall_windows.go#L235
	r1, _, e1 := syscall.Syscall(procLookupPrivilegeValueW.Addr(), 3, uintptr(unsafe.Pointer(systemname)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(luid)))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

type Handle uintptr
type Token Handle

type TOKEN_PRIVILEGES struct { // https://golang.org/src/internal/syscall/windows/security_windows.go#L36
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

func adjustTokenPrivileges(token syscall.Token, disableAllPrivileges bool, newstate *TOKEN_PRIVILEGES, buflen uint32, prevstate *TOKEN_PRIVILEGES, returnlen *uint32) (err error) { // https://golang.org/src/internal/syscall/windows/security_windows.go#L45
	var _p0 uint32 // inlining https://golang.org/src/internal/syscall/windows/zsyscall_windows.go#L214
	if disableAllPrivileges {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r0, _, e1 := syscall.Syscall6(procAdjustTokenPrivileges.Addr(), 6, uintptr(token), uintptr(_p0), uintptr(unsafe.Pointer(newstate)), uintptr(buflen), uintptr(unsafe.Pointer(prevstate)), uintptr(unsafe.Pointer(returnlen)))
	var ret = uint32(r0)
	if true {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	if ret == 0 {
		// AdjustTokenPrivileges call failed
		return err
	}
	// AdjustTokenPrivileges call succeeded
	if err == syscall.EINVAL {
		// GetLastError returned ERROR_SUCCESS
		return nil
	}
	return err
}

func enableSeDebugPrivilege() error {
	const TOKEN_QUERY = 4 // https://golang.org/src/syscall/security_windows.go#L219
	const TOKEN_ADJUST_PRIVILEGES = 6
	pseudoHandle, err := getCurrentProcess()
	if err != nil {
		return err
	}
	var hToken syscall.Token
	err = openProcessToken(pseudoHandle, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)
	if err != nil {
		return err
	}
	defer hToken.Close()

	var luidSEDebugNameValue LUID
	var tkpPrivileges TOKEN_PRIVILEGES
	SeDebugPrivilege, err := syscall.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return err
	}
	err = lookupPrivilegeValue(nil, SeDebugPrivilege, &luidSEDebugNameValue)
	if err != nil {
		return err
	}

	tkpPrivileges.PrivilegeCount = 1
	tkpPrivileges.Privileges[0].Luid = luidSEDebugNameValue
	tkpPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	err = adjustTokenPrivileges(hToken, false, &tkpPrivileges, 0, nil, nil)
	if err != nil {
		return err
	}
	return nil
}
