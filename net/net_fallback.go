// +build !darwin,!linux,!freebsd,!openbsd,!windows

package net

import (
	"context"

	"github.com/shirou/gopsutil/internal/common"
)

func IOCounters(pernic bool) ([]IOCountersStat, error) {
	return IOCountersWithContext(context.Background(), pernic)
}

func IOCountersWithContext(ctx context.Context, pernic bool) ([]IOCountersStat, error) {
	return []IOCountersStat{}, common.ErrNotImplementedError
}

func IOCountersByFile(pernic bool, filename string) ([]IOCountersStat, error) {
	return IOCountersByFileWithContext(context.Background(), pernic, filename)
}

func IOCountersByFileWithContext(ctx context.Context, pernic bool, filename string) ([]IOCountersStat, error) {
	return IOCounters(pernic)
}

func FilterCounters() ([]FilterStat, error) {
	return FilterCountersWithContext(context.Background())
}

func FilterCountersWithContext(ctx context.Context) ([]FilterStat, error) {
	return []FilterStat{}, common.ErrNotImplementedError
}

func ProtoCounters(protocols []string) ([]ProtoCountersStat, error) {
	return ProtoCountersWithContext(context.Background(), protocols)
}

func ProtoCountersWithContext(ctx context.Context, protocols []string) ([]ProtoCountersStat, error) {
	return []ProtoCountersStat{}, common.ErrNotImplementedError
}

func Connections(kind string) ([]ConnectionStat, error) {
	return ConnectionsWithContext(context.Background(), kind)
}

func ConnectionsWithContext(ctx context.Context, kind string) ([]ConnectionStat, error) {
	return []ConnectionStat{}, common.ErrNotImplementedError
}

func ConnectionsMax(kind string, max int) ([]ConnectionStat, error) {
	return ConnectionsMaxWithContext(context.Background(), kind, max)
}

func ConnectionsMaxWithContext(ctx context.Context, kind string, max int) ([]ConnectionStat, error) {
	return []ConnectionStat{}, common.ErrNotImplementedError
}

func ConnectionsPid(kind string, pid int32) ([]ConnectionStat, error) {
	return ConnectionsPidWithContext(context.Background(), kind, pid)
}

func ConnectionsPidWithContext(ctx context.Context, kind string, pid int32) ([]ConnectionStat, error) {
	return []ConnectionStat{}, common.ErrNotImplementedError
}

func ConnectionsPidMax(kind string, pid int32, max int) ([]ConnectionStat, error) {
	return ConnectionsPidMaxWithContext(context.Background(), kind, pid, max)
}

func ConnectionsPidMaxWithContext(ctx context.Context, kind string, pid int32, max int) ([]ConnectionStat, error) {
	return []ConnectionStat{}, common.ErrNotImplementedError
}

func Pids() ([]int32, error) {
	return PidsWithContext(context.Background())
}

func PidsWithContext(ctx context.Context) ([]int32, error) {
	return []int32{}, common.ErrNotImplementedError
}
