// +build windows

package cpu

import (
	"encoding/binary"
)

// https://github.com/DataDog/gohai/blob/8cbe900337f170d59939592f4f2f7bddf8d1c5b5/cpu/cpu_windows_amd64.go
const systemLogicalProcessorInformationSize = 32

func byteArraytoSystemLogicalProcessorInformation(data []byte) (info systemLogicalProcessorInformation) {
	info.ProcessorMask = uintptr(binary.LittleEndian.Uint64(data))
	info.Relationship = int(binary.LittleEndian.Uint64(data[8:]))
	copy(info.dataunion[0:16], data[16:systemLogicalProcessorInformationSize])
	return
}
