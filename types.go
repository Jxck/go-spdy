// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package spdy implements HTTP2.0 (SPDY/3) protocol which is described in
// http://tools.ietf.org/html/draft-ietf-httpbis-http2-00
package spdy

import (
	"bytes"
	"compress/zlib"
	"io"
	"net/http"
)

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

// MaxDataLength is the maximum number of bytes
// that can be stored in one frame.
const MaxDataLength = 1<<24 - 1

// Separator for multiple Header Values
const HeaderValueSeparator = "\x00"

// Frame is a single SPDY frame in its unpacked in-memory representation.
// Use Framer to read and write it.
type Frame interface {
	write(f *Framer) error
}

// ControlFrameHeader contains all the fields in a control frame header,
// in its unpacked in-memory representation.
//
//  Control Frame Format
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   |
//  +----------------------------------+
//  |               Data               |
//  +----------------------------------+
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
//
//  Control Frame: SYN_STREAM (18 + length)
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
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
//
//  Control Frame: SYN_REPLY (24 + length)
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
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
//
//  Control Frame: RST_STREAM (16 byte)
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0, length = 8
//  +----------------------------------+
//  |X|       Stream-ID(31bits)        |
//  +----------------------------------+
//  |        Status code (32 bits)     |
//  +----------------------------------+
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

// SettingsFlagIdValue is the unpacked,
// in-memory representation of the combined
// flag/id/value for a setting in a SETTINGS frame.
type SettingsFlagIdValue struct {
	Flag  SettingsFlag
	Id    SettingsId
	Value uint32
}

// SettingsFrame is the unpacked,
// in-memory representation of a SPDY SETTINGS frame.
//
//  Control Frame: SETTINGS (8 + length)
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0x1(FLAG_SETTINGS_CLEAR_SETINGS)
//  +----------------------------------+
//  | ID.flags (8) | Unique ID (24)    |
//  +----------------------------------+
//  |          Value (32)              |
//  +----------------------------------+
type SettingsFrame struct {
	CFHeader     ControlFrameHeader
	FlagIdValues []SettingsFlagIdValue
}

// PingFrame is the unpacked,
// in-memory representation of a PING frame.
//
//  Control Frame: PING (12)
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0, length = 4
//  +----------------------------------+
//  |        Unique id (32 bits)       |
//  +----------------------------------+
type PingFrame struct {
	CFHeader ControlFrameHeader
	Id       uint32
}

// GoAwayFrame is the unpacked,
// in-memory representation of a GOAWAY frame.
//
//  Control Frame: GOAWAY
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0, length = 8
//  +----------------------------------+
//  |X| Last-accepted-stream-id(31bits)|
//  +----------------------------------+
//  |           Status code            | 0 = OK, 1 = PROTOCOL_ERROR, 11 = INTERNAL_ERROR
//  +----------------------------------+
type GoAwayFrame struct {
	CFHeader         ControlFrameHeader
	LastGoodStreamId uint32
	Status           uint32
	// TODO: StatusCode is better
}

// HeadersFrame is the unpacked,
// in-memory representation of a HEADERS frame.
//
//  Control Frame: HEADERS (12 + length)
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
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
type HeadersFrame struct {
	CFHeader ControlFrameHeader
	StreamId uint32
	Headers  http.Header
}

// WindowUpdateFrame is the unpacked,
// in-memory representation of a WINDOW_UPDATE frame.
//
//  Control Frame: WINDOW_UPDATE
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0, lenght = 8
//  +----------------------------------+
//  |X|      Stream-ID (31 bits)       |
//  +----------------------------------+
//  |X|  Delta-Window-Size (31 bits)   |
//  +----------------------------------+
type WindowUpdateFrame struct {
	CFHeader        ControlFrameHeader
	StreamId        uint32
	DeltaWindowSize uint32
}

//  TODO: impliment
//  Control Frame: CREDENTIAL
//  +----------------------------------+
//  |1| Version(15bits) | Type(16bits) |
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

// DataFrame is the unpacked,
// in-memory representation of a DATA frame.
//
//  Data Frame Format
//  +----------------------------------+
//  |0|       Stream-ID (31bits)       |
//  +----------------------------------+
//  | flags (8)  |  Length (24 bits)   | flags = 0x01(FLAG_FIN) or 0x02(FLAG_COMPRESS)
//  +----------------------------------+
//  |               Data               |
//  +----------------------------------+
type DataFrame struct {
	// Note, high bit is the "Control" bit.
	// Should be 0 for data frames.
	StreamId uint32
	Flags    DataFlags
	Data     []byte
}

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

// Framer handles serializing/deserializing SPDY frames,
// including compressing/decompressing payloads.
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
