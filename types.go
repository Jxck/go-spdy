// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package spdy implements the SPDY protocol (currently SPDY/3), described in
// http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3.
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
const (
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

// headerValueSepator separates multiple header values.
const headerValueSeparator = "\x00"

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

// SynStreamFrame is the unpacked, in-memory representation of a SYN_STREAM
// frame.
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

// SynReplyFrame is the unpacked, in-memory representation of a SYN_REPLY frame.
type SynReplyFrame struct {
	CFHeader ControlFrameHeader
	StreamId uint32
	Headers  http.Header
}

// RstStreamStatus represents the status that led to a RST_STREAM.
type RstStreamStatus uint32

const (
	_ RstStreamStatus = iota
	ProtocolError
	InvalidStream
	RefusedStream
	UnsupportedVersion
	Cancel
	InternalError
	FlowControlError
	StreamInUse
	StreamAlreadyClosed
	InvalidCredentials
	FrameTooLarge
)

// RstStreamFrame is the unpacked, in-memory representation of a RST_STREAM
// frame.
type RstStreamFrame struct {
	CFHeader ControlFrameHeader
	StreamId uint32
	Status   RstStreamStatus
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
	_ SettingsId = iota
	SettingsUploadBandwidth
	SettingsDownloadBandwidth
	SettingsRoundTripTime
	SettingsMaxConcurrentStreams
	SettingsCurrentCwnd
	SettingsDownloadRetransRate
	SettingsInitialWindowSize
	SettingsClientCretificateVectorSize
)

// SettingsFlagIdValue is the unpacked, in-memory representation of the
// combined flag/id/value for a setting in a SETTINGS frame.
type SettingsFlagIdValue struct {
	Flag  SettingsFlag
	Id    SettingsId
	Value uint32
}

// SettingsFrame is the unpacked, in-memory representation of a SPDY
// SETTINGS frame.
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

// GoAwayFrame is the unpacked, in-memory representation of a GOAWAY frame.
type GoAwayStatus uint32

const (
	GoAwayOK            GoAwayStatus = 0
	GoAwayProtocolError              = 1
	GoAwayInternalError              = 11
)

type GoAwayFrame struct {
	CFHeader         ControlFrameHeader
	LastGoodStreamId uint32
	Status           GoAwayStatus
}

// HeadersFrame is the unpacked, in-memory representation of a HEADERS frame.
type HeadersFrame struct {
	CFHeader ControlFrameHeader
	StreamId uint32
	Headers  http.Header
}

// WindowUpdateFrame is the unpacked, in-memory representation of a
// WINDOW_UPDATE frame.
type WindowUpdateFrame struct {
	CFHeader        ControlFrameHeader
	StreamId        uint32
	DeltaWindowSize uint32
}

// TODO: Implement credential frame and related methods

// DataFrame is the unpacked, in-memory representation of a DATA frame.
type DataFrame struct {
	// Note, high bit is the "Control" bit. Should be 0 for data frames.
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
	compressor, err := zlib.NewWriterLevelDict(compressBuf, zlib.BestCompression, []byte(headerDictionary))
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
