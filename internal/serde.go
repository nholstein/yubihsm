package yubihsm

import (
	"encoding/binary"
)

func Append[V ~[]byte](b []byte, v V) []byte {
	return append(b, v...)
}

func Append8[V ~uint8 | ~int8 | ~int](b []byte, v V) []byte {
	return append(b, byte(v))
}

func Append16[V ~uint16 | ~int16 | ~int](b []byte, v V) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(v))
}

//func Append32[V ~uint32 | ~int32 | ~int](b []byte, v V) []byte {
//	return binary.BigEndian.AppendUint32(b, uint32(v))
//}

func Put8[V ~uint8 | ~int8 | ~int](b []byte, v V) {
	b[0] = byte(v)
}

func Put16[V ~uint16 | ~int16 | ~int](b []byte, v V) {
	binary.BigEndian.PutUint16(b, uint16(v))
}

func Put32[V ~uint32 | ~int32 | ~int](b []byte, v V) {
	binary.BigEndian.PutUint32(b, uint32(v))
}

func Parse8[V ~uint8 | ~int8](b []byte, o int, v *V) {
	*v = V(uint8(b[o]))
}

func Parse16[V ~uint16 | ~int16](b []byte, o int, v *V) {
	*v = V(uint16(b[o])<<8 | uint16(b[o+1]))
}

func Parse32[V ~uint32 | ~int32](b []byte, o int, v *V) {
	*v = V(uint32(b[o])<<24 | uint32(b[o+1])<<16 | uint32(b[o+2])<<8 | uint32(b[o+3]))
}

func ParseHeader(b []byte) (CommandID, int) {
	// Each message has a 1 byte command ID and 2 byte length
	return CommandID(b[0]), int(b[1])<<8 | int(b[2])
}
