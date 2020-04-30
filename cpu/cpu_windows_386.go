// +build windows

package cpu

import (
	"encoding/binary"
)

// https://github.com/DataDog/gohai/blob/8cbe900337f170d59939592f4f2f7bddf8d1c5b5/cpu/cpu_windows_386.go
const systemLogicalProcessorInformationSize = 24

func byteArraytoSystemLogicalProcessorInformation(data []byte) (info systemLogicalProcessorInformation) {
	info.ProcessorMask = uintptr(binary.LittleEndian.Uint32(data))
	info.Relationship = int(binary.LittleEndian.Uint32(data[4:]))
	copy(info.dataunion[0:16], data[8:systemLogicalProcessorInformationSize])
	return
}
