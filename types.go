// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package spdy implements SPDY protocol which is described in
// draft-mbelshe-httpbis-spdy-00.
//
// http://tools.ietf.org/html/draft-mbelshe-httpbis-spdy-00
package spdy

import (
	"bytes"
	"compress/zlib"
	"io"
	"net/http"
)

//  Data Frame Format
//  +----------------------------------+
//  |0|       Stream-ID (31bits)       |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   |
//  +----------------------------------+
//  |               Data               |
//  +----------------------------------+
//
//  Control Frame Format
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   |
//  +----------------------------------+
//  |               Data               |
//  +----------------------------------+
//
//  Control Frame: SYN_STREAM (18 + length)
//  +----------------------------------+
//  |1|000000000000011|0000000000000001|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0x01(FLAG_FIN), 0x02(FLAG_UNIDIRECTIONAL)
//  +----------------------------------+
//  |X|       Stream-ID(31bits)        | <-+
//  +----------------------------------+   |
//  |X|Associated-To-Stream-ID (31bits)|   | 10byte
//  +----------------------------------+   |
//  |Pri(3)|unused(5)|SLOT(8bits)|     | <-+
//  +----------------------------------+
//  | # of Name/Value pair(int 32)     | <-+
//  +----------------------------------+   | compressed
//  |     Length of name (int 32)      |   |
//  +----------------------------------+   |
//  |          Name (String)           |   |
//  +----------------------------------+   |
//  |     Length of value (int 32)     |   |
//  +----------------------------------+   |
//  |          Value (String)          |   |
//  +----------------------------------+   |
//  |            (repeat)              | <-+
//  +----------------------------------+
//
//  Control Frame: SYN_REPLY (24 + length)
//  +----------------------------------+
//  |1|000000000000011|0000000000000010|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0x01(FLAG_FIN)
//  +----------------------------------+
//  |X|       Stream-ID(31bits)        |
//  +----------------------------------+
//  | # of Name/Value pair(int 32)     | <-+
//  +----------------------------------+   | compressed
//  |     Length of name (int 32)      |   |
//  +----------------------------------+   |
//  |          Name (String)           |   |
//  +----------------------------------+   |
//  |     Length of value (int 32)     |   |
//  +----------------------------------+   |
//  |          Value (String)          |   |
//  +----------------------------------+   |
//  |            (repeat)              | <-+
//  +----------------------------------+
//
//  Control Frame: RST_STREAM (16 byte)
//  +----------------------------------+
//  |1|000000000000011|0000000000000011|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0, length = 8
//  +----------------------------------+
//  |X|       Stream-ID(31bits)        |
//  +----------------------------------+
//  |        Status code (32 bits)     |
//  +----------------------------------+
//
//  Control Frame: SETTINGS (8 + length)
//  +----------------------------------+
//  |1|000000000000011|0000000000000100|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0x1(FLAG_SETTINGS_CLEAR_SETINGS)
//  +----------------------------------+
//  | ID.flags (8) | Unique ID (24)    |
//  +----------------------------------+
//  |          Value (32)              |
//  +----------------------------------+
//
//  Control Frame: PING (12)
//  +----------------------------------+
//  |1|000000000000011|0000000000000110|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0, length = 4
//  +----------------------------------+
//  |        Unique id (32 bits)       |
//  +----------------------------------+
//
//  Control Frame: GOAWAY
//  +----------------------------------+
//  |1|000000000000011|0000000000000111|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0, length = 8
//  +----------------------------------+
//  |X| Last-accepted-stream-id(31bits)|
//  +----------------------------------+
//  |           Status code            | 0 = OK, 1 = PROTOCOL_ERROR, 11 = INTERNAL_ERROR
//  +----------------------------------+
//
//  Control Frame: HEADERS (12 + length)
//  +----------------------------------+
//  |1|000000000000011|0000000000001000|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0x01 (FLAG_FIN), Length >= 4
//  +----------------------------------+
//  |X|      Stream-ID (31 bits)       |
//  +----------------------------------+
//  | # of Name/Value pair(int 32)     | <-+
//  +----------------------------------+   | compressed
//  |     Length of name (int 32)      |   |
//  +----------------------------------+   |
//  |          Name (String)           |   |
//  +----------------------------------+   |
//  |     Length of value (int 32)     |   |
//  +----------------------------------+   |
//  |          Value (String)          |   |
//  +----------------------------------+   |
//  |            (repeat)              | <-+
//  +----------------------------------+
//
//  Control Frame: WINDOW_UPDATE
//  +----------------------------------+
//  |1|000000000000011|0000000000001001|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0, lenght = 8
//  +----------------------------------+
//  |X|      Stream-ID (31 bits)       |
//  +----------------------------------+
//  |X|  Delta-Window-Size (31 bits)   |
//  +----------------------------------+
//
//  TODO: impliment
//  Control Frame: CREDENTIAL
//  +----------------------------------+
//  |1|000000000000001|0000000000001011|
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   |
//  +----------------------------------+
//  |  Slot (16 bits) |                |
//  +-----------------+                |
//  |      Proof Length (32 bits)      |
//  +----------------------------------+
//  |               Proof              |
//  +----------------------------------+ <+
//  |   Certificate Length (32 bits)   |  |
//  +----------------------------------+  | Repeated until end of frame
//  |            Certificate           |  |
//  +----------------------------------+ <+

// Version is the protocol version number that this package implements.
const Version = 3

// ControlFrameType stores the type field in a control frame header.
type ControlFrameType uint16

// Control frame type constants
const ( // Noop (0x0005) removed spdy/3
	TypeSynStream    ControlFrameType = 0x0001
	TypeSynReply                      = 0x0002
	TypeRstStream                     = 0x0003
	TypeSettings                      = 0x0004
	TypePing                          = 0x0006
	TypeGoAway                        = 0x0007
	TypeHeaders                       = 0x0008
	TypeWindowUpdate                  = 0x0009
)

// ControlFlags are the flags that can be set on a control frame.
type ControlFlags uint8

const (
	ControlFlagFin ControlFlags = 0x01
)

// DataFlags are the flags that can be set on a data frame.
type DataFlags uint8

const (
	DataFlagFin        DataFlags = 0x01
	DataFlagCompressed           = 0x02
)

// MaxDataLength is the maximum number of bytes that can be stored in one frame.
const MaxDataLength = 1<<24 - 1

// Frame is a single SPDY frame in its unpacked in-memory representation. Use
// Framer to read and write it.
type Frame interface {
	write(f *Framer) error
}

// ControlFrameHeader contains all the fields in a control frame header,
// in its unpacked in-memory representation.
type ControlFrameHeader struct {
	// Note, high bit is the "Control" bit.
	version   uint16
	frameType ControlFrameType
	Flags     ControlFlags
	length    uint32
}

type controlFrame interface {
	Frame
	read(h ControlFrameHeader, f *Framer) error
}

// SynStreamFrame is the unpacked,
// in-memory representation of a SYN_STREAM frame.
type SynStreamFrame struct {
	CFHeader             ControlFrameHeader
	StreamId             uint32
	AssociatedToStreamId uint32
	// Note, only 3 highest bits currently used
	// Rest of Priority is unused.
	Priority uint8
	Slot     uint8
	Headers  http.Header
}

// SynReplyFrame is the unpacked,
// in-memory representation of a SYN_REPLY frame.
type SynReplyFrame struct {
	CFHeader ControlFrameHeader
	StreamId uint32
	Headers  http.Header
}

// RSTStatusCode represents the status that led to a RST_STREAM
type RSTStatusCode uint32

const ( // 0 is invalid
	ProtocolError         RSTStatusCode = 1
	InvalidStream                       = 2
	RefusedStream                       = 3
	UnsupportedVersion                  = 4
	Cancel                              = 5
	InternalError                       = 6
	FlowControlError                    = 7
	STREAM_IN_USE                       = 8
	STREAM_ALREADY_CLOSED               = 9
	INVALID_CREDENTIALS                 = 10
	FRAME_TOO_LARGE                     = 11
)

// RstStreamFrame is the unpacked,
// in-memory representation of a RST_STREAM
// frame.
type RstStreamFrame struct {
	CFHeader ControlFrameHeader
	StreamId uint32
	Status   RSTStatusCode
}

// SettingsFlag represents a flag in a SETTINGS frame.
type SettingsFlag uint8

const (
	FlagSettingsPersistValue SettingsFlag = 0x1
	FlagSettingsPersisted                 = 0x2
)

// SettingsFlag represents the id of an id/value pair in a SETTINGS frame.
type SettingsId uint32

const (
	SettingsUploadBandwidth             SettingsId = 1
	SettingsDownloadBandwidth                      = 2
	SettingsRoundTripTime                          = 3
	SettingsMaxConcurrentStreams                   = 4
	SettingsCurrentCwnd                            = 5
	SettingsDownloadRetransRate                    = 6
	SettingsInitialWindowSize                      = 7
	SettingsClientCretificateVectorSize            = 8
)

// SettingsFlagIdValue is the unpacked, in-memory representation of the
// combined flag/id/value for a setting in a SETTINGS frame.
type SettingsFlagIdValue struct {
	Flag  SettingsFlag
	Id    SettingsId
	Value uint32
}

// SettingsFrame is the unpacked,
// in-memory representation of a SPDY SETTINGS frame.
type SettingsFrame struct {
	CFHeader     ControlFrameHeader
	FlagIdValues []SettingsFlagIdValue
}

// PingFrame is the unpacked,
// in-memory representation of a PING frame.
type PingFrame struct {
	CFHeader ControlFrameHeader
	Id       uint32
}

// GoAwayFrame is the unpacked,
// in-memory representation of a GOAWAY frame.
type GoAwayFrame struct {
	CFHeader         ControlFrameHeader
	LastGoodStreamId uint32
	Status           uint32
	// TODO: StatusCode is better
}

// HeadersFrame is the unpacked, in-memory representation of a HEADERS frame.
type HeadersFrame struct {
	CFHeader ControlFrameHeader
	StreamId uint32
	Headers  http.Header
}

// WindowUpdateFrame is the unpacked,
// in-memory representation of a WINDOW_UPDATE frame.
type WindowUpdateFrame struct {
	CFHeader        ControlFrameHeader
	StreamId        uint32
	DeltaWindowSize uint32
}

// DataFrame is the unpacked, in-memory representation of a DATA frame.
type DataFrame struct {
	// Note, high bit is the "Control" bit. Should be 0 for data frames.
	StreamId uint32
	Flags    DataFlags
	Data     []byte
}

// HeaderDictionary is the dictionary sent to the zlib compressor/decompressor.
// Even though the specification states there is no null byte at the end, Chrome sends it.
const HeaderDictionary = "\x00\x00\x00\x07\x6f\x70\x74\x69\x6f\x6e\x73\x00\x00\x00\x04\x68\x65" +
	"\x61\x64\x00\x00\x00\x04\x70\x6f\x73\x74\x00\x00\x00\x03\x70\x75\x74" +
	"\x00\x00\x00\x06\x64\x65\x6c\x65\x74\x65\x00\x00\x00\x05\x74\x72\x61" +
	"\x63\x65\x00\x00\x00\x06\x61\x63\x63\x65\x70\x74\x00\x00\x00\x0e\x61" +
	"\x63\x63\x65\x70\x74\x2d\x63\x68\x61\x72\x73\x65\x74\x00\x00\x00\x0f" +
	"\x61\x63\x63\x65\x70\x74\x2d\x65\x6e\x63\x6f\x64\x69\x6e\x67\x00\x00" +
	"\x00\x0f\x61\x63\x63\x65\x70\x74\x2d\x6c\x61\x6e\x67\x75\x61\x67\x65" +
	"\x00\x00\x00\x0d\x61\x63\x63\x65\x70\x74\x2d\x72\x61\x6e\x67\x65\x73" +
	"\x00\x00\x00\x03\x61\x67\x65\x00\x00\x00\x05\x61\x6c\x6c\x6f\x77\x00" +
	"\x00\x00\x0d\x61\x75\x74\x68\x6f\x72\x69\x7a\x61\x74\x69\x6f\x6e\x00" +
	"\x00\x00\x0d\x63\x61\x63\x68\x65\x2d\x63\x6f\x6e\x74\x72\x6f\x6c\x00" +
	"\x00\x00\x0a\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x00\x00\x00\x0c" +
	"\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x62\x61\x73\x65\x00\x00\x00\x10\x63" +
	"\x6f\x6e\x74\x65\x6e\x74\x2d\x65\x6e\x63\x6f\x64\x69\x6e\x67\x00\x00" +
	"\x00\x10\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x61\x6e\x67\x75\x61\x67" +
	"\x65\x00\x00\x00\x0e\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67" +
	"\x74\x68\x00\x00\x00\x10\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x6f\x63" +
	"\x61\x74\x69\x6f\x6e\x00\x00\x00\x0b\x63\x6f\x6e\x74\x65\x6e\x74\x2d" +
	"\x6d\x64\x35\x00\x00\x00\x0d\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x72\x61" +
	"\x6e\x67\x65\x00\x00\x00\x0c\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x74\x79" +
	"\x70\x65\x00\x00\x00\x04\x64\x61\x74\x65\x00\x00\x00\x04\x65\x74\x61" +
	"\x67\x00\x00\x00\x06\x65\x78\x70\x65\x63\x74\x00\x00\x00\x07\x65\x78" +
	"\x70\x69\x72\x65\x73\x00\x00\x00\x04\x66\x72\x6f\x6d\x00\x00\x00\x04" +
	"\x68\x6f\x73\x74\x00\x00\x00\x08\x69\x66\x2d\x6d\x61\x74\x63\x68\x00" +
	"\x00\x00\x11\x69\x66\x2d\x6d\x6f\x64\x69\x66\x69\x65\x64\x2d\x73\x69" +
	"\x6e\x63\x65\x00\x00\x00\x0d\x69\x66\x2d\x6e\x6f\x6e\x65\x2d\x6d\x61" +
	"\x74\x63\x68\x00\x00\x00\x08\x69\x66\x2d\x72\x61\x6e\x67\x65\x00\x00" +
	"\x00\x13\x69\x66\x2d\x75\x6e\x6d\x6f\x64\x69\x66\x69\x65\x64\x2d\x73" +
	"\x69\x6e\x63\x65\x00\x00\x00\x0d\x6c\x61\x73\x74\x2d\x6d\x6f\x64\x69" +
	"\x66\x69\x65\x64\x00\x00\x00\x08\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x00" +
	"\x00\x00\x0c\x6d\x61\x78\x2d\x66\x6f\x72\x77\x61\x72\x64\x73\x00\x00" +
	"\x00\x06\x70\x72\x61\x67\x6d\x61\x00\x00\x00\x12\x70\x72\x6f\x78\x79" +
	"\x2d\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65\x00\x00\x00\x13" +
	"\x70\x72\x6f\x78\x79\x2d\x61\x75\x74\x68\x6f\x72\x69\x7a\x61\x74\x69" +
	"\x6f\x6e\x00\x00\x00\x05\x72\x61\x6e\x67\x65\x00\x00\x00\x07\x72\x65" +
	"\x66\x65\x72\x65\x72\x00\x00\x00\x0b\x72\x65\x74\x72\x79\x2d\x61\x66" +
	"\x74\x65\x72\x00\x00\x00\x06\x73\x65\x72\x76\x65\x72\x00\x00\x00\x02" +
	"\x74\x65\x00\x00\x00\x07\x74\x72\x61\x69\x6c\x65\x72\x00\x00\x00\x11" +
	"\x74\x72\x61\x6e\x73\x66\x65\x72\x2d\x65\x6e\x63\x6f\x64\x69\x6e\x67" +
	"\x00\x00\x00\x07\x75\x70\x67\x72\x61\x64\x65\x00\x00\x00\x0a\x75\x73" +
	"\x65\x72\x2d\x61\x67\x65\x6e\x74\x00\x00\x00\x04\x76\x61\x72\x79\x00" +
	"\x00\x00\x03\x76\x69\x61\x00\x00\x00\x07\x77\x61\x72\x6e\x69\x6e\x67" +
	"\x00\x00\x00\x10\x77\x77\x77\x2d\x61\x75\x74\x68\x65\x6e\x74\x69\x63" +
	"\x61\x74\x65\x00\x00\x00\x06\x6d\x65\x74\x68\x6f\x64\x00\x00\x00\x03" +
	"\x67\x65\x74\x00\x00\x00\x06\x73\x74\x61\x74\x75\x73\x00\x00\x00\x06" +
	"\x32\x30\x30\x20\x4f\x4b\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e" +
	"\x00\x00\x00\x08\x48\x54\x54\x50\x2f\x31\x2e\x31\x00\x00\x00\x03\x75" +
	"\x72\x6c\x00\x00\x00\x06\x70\x75\x62\x6c\x69\x63\x00\x00\x00\x0a\x73" +
	"\x65\x74\x2d\x63\x6f\x6f\x6b\x69\x65\x00\x00\x00\x0a\x6b\x65\x65\x70" +
	"\x2d\x61\x6c\x69\x76\x65\x00\x00\x00\x06\x6f\x72\x69\x67\x69\x6e\x31" +
	"\x30\x30\x31\x30\x31\x32\x30\x31\x32\x30\x32\x32\x30\x35\x32\x30\x36" +
	"\x33\x30\x30\x33\x30\x32\x33\x30\x33\x33\x30\x34\x33\x30\x35\x33\x30" +
	"\x36\x33\x30\x37\x34\x30\x32\x34\x30\x35\x34\x30\x36\x34\x30\x37\x34" +
	"\x30\x38\x34\x30\x39\x34\x31\x30\x34\x31\x31\x34\x31\x32\x34\x31\x33" +
	"\x34\x31\x34\x34\x31\x35\x34\x31\x36\x34\x31\x37\x35\x30\x32\x35\x30" +
	"\x34\x35\x30\x35\x32\x30\x33\x20\x4e\x6f\x6e\x2d\x41\x75\x74\x68\x6f" +
	"\x72\x69\x74\x61\x74\x69\x76\x65\x20\x49\x6e\x66\x6f\x72\x6d\x61\x74" +
	"\x69\x6f\x6e\x32\x30\x34\x20\x4e\x6f\x20\x43\x6f\x6e\x74\x65\x6e\x74" +
	"\x33\x30\x31\x20\x4d\x6f\x76\x65\x64\x20\x50\x65\x72\x6d\x61\x6e\x65" +
	"\x6e\x74\x6c\x79\x34\x30\x30\x20\x42\x61\x64\x20\x52\x65\x71\x75\x65" +
	"\x73\x74\x34\x30\x31\x20\x55\x6e\x61\x75\x74\x68\x6f\x72\x69\x7a\x65" +
	"\x64\x34\x30\x33\x20\x46\x6f\x72\x62\x69\x64\x64\x65\x6e\x34\x30\x34" +
	"\x20\x4e\x6f\x74\x20\x46\x6f\x75\x6e\x64\x35\x30\x30\x20\x49\x6e\x74" +
	"\x65\x72\x6e\x61\x6c\x20\x53\x65\x72\x76\x65\x72\x20\x45\x72\x72\x6f" +
	"\x72\x35\x30\x31\x20\x4e\x6f\x74\x20\x49\x6d\x70\x6c\x65\x6d\x65\x6e" +
	"\x74\x65\x64\x35\x30\x33\x20\x53\x65\x72\x76\x69\x63\x65\x20\x55\x6e" +
	"\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\x4a\x61\x6e\x20\x46\x65\x62\x20" +
	"\x4d\x61\x72\x20\x41\x70\x72\x20\x4d\x61\x79\x20\x4a\x75\x6e\x20\x4a" +
	"\x75\x6c\x20\x41\x75\x67\x20\x53\x65\x70\x74\x20\x4f\x63\x74\x20\x4e" +
	"\x6f\x76\x20\x44\x65\x63\x20\x30\x30\x3a\x30\x30\x3a\x30\x30\x20\x4d" +
	"\x6f\x6e\x2c\x20\x54\x75\x65\x2c\x20\x57\x65\x64\x2c\x20\x54\x68\x75" +
	"\x2c\x20\x46\x72\x69\x2c\x20\x53\x61\x74\x2c\x20\x53\x75\x6e\x2c\x20" +
	"\x47\x4d\x54\x63\x68\x75\x6e\x6b\x65\x64\x2c\x74\x65\x78\x74\x2f\x68" +
	"\x74\x6d\x6c\x2c\x69\x6d\x61\x67\x65\x2f\x70\x6e\x67\x2c\x69\x6d\x61" +
	"\x67\x65\x2f\x6a\x70\x67\x2c\x69\x6d\x61\x67\x65\x2f\x67\x69\x66\x2c" +
	"\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x6d\x6c\x2c\x61" +
	"\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c\x2b" +
	"\x78\x6d\x6c\x2c\x74\x65\x78\x74\x2f\x70\x6c\x61\x69\x6e\x2c\x74\x65" +
	"\x78\x74\x2f\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74\x2c\x70\x75\x62" +
	"\x6c\x69\x63\x70\x72\x69\x76\x61\x74\x65\x6d\x61\x78\x2d\x61\x67\x65" +
	"\x3d\x67\x7a\x69\x70\x2c\x64\x65\x66\x6c\x61\x74\x65\x2c\x73\x64\x63" +
	"\x68\x63\x68\x61\x72\x73\x65\x74\x3d\x75\x74\x66\x2d\x38\x63\x68\x61" +
	"\x72\x73\x65\x74\x3d\x69\x73\x6f\x2d\x38\x38\x35\x39\x2d\x31\x2c\x75" +
	"\x74\x66\x2d\x2c\x2a\x2c\x65\x6e\x71\x3d\x30\x2e"

// A SPDY specific error.
type ErrorCode string

const (
	UnlowercasedHeaderName     ErrorCode = "header was not lowercased"
	DuplicateHeaders           ErrorCode = "multiple headers with same name"
	WrongCompressedPayloadSize ErrorCode = "compressed payload size was incorrect"
	UnknownFrameType           ErrorCode = "unknown frame type"
	InvalidControlFrame        ErrorCode = "invalid control frame"
	InvalidDataFrame           ErrorCode = "invalid data frame"
	InvalidHeaderPresent       ErrorCode = "frame contained invalid header"
	ZeroStreamId               ErrorCode = "stream id zero is disallowed"
)

// Error contains both the type of error and additional values. StreamId is 0
// if Error is not associated with a stream.
type Error struct {
	Err      ErrorCode
	StreamId uint32
}

func (e *Error) Error() string {
	return string(e.Err)
}

// TODO: need this ?
// var mustReqHeaders = map[string]bool{
// 	"method":  true,
// 	"host":    true,
// 	"path":    true,
// 	"scheme":  true,
// 	"version": true,
// }

var invalidReqHeaders = map[string]bool{
	"Connection":        true,
	"Host":              true,
	"Keep-Alive":        true,
	"Proxy-Connection":  true,
	"Transfer-Encoding": true,
}

var invalidRespHeaders = map[string]bool{
	"Connection":        true,
	"Keep-Alive":        true,
	"Proxy-Connection":  true,
	"Transfer-Encoding": true,
}

// Framer handles serializing/deserializing SPDY frames, including compressing/
// decompressing payloads.
type Framer struct {
	headerCompressionDisabled bool
	w                         io.Writer
	headerBuf                 *bytes.Buffer
	headerCompressor          *zlib.Writer
	r                         io.Reader
	headerReader              io.LimitedReader
	headerDecompressor        io.ReadCloser
}

// NewFramer allocates a new Framer for a given SPDY connection, repesented by
// a io.Writer and io.Reader. Note that Framer will read and write individual fields
// from/to the Reader and Writer, so the caller should pass in an appropriately
// buffered implementation to optimize performance.
func NewFramer(w io.Writer, r io.Reader) (*Framer, error) {
	compressBuf := new(bytes.Buffer)
	compressor, err := zlib.NewWriterLevelDict(compressBuf, zlib.BestCompression, []byte(HeaderDictionary))
	if err != nil {
		return nil, err
	}
	framer := &Framer{
		w:                w,
		headerBuf:        compressBuf,
		headerCompressor: compressor,
		r:                r,
	}
	return framer, nil
}
