// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spdy

import (
	"encoding/binary"
	"io"
	"net/http"
	"strings"
)

// Writes a frame to SynStreamFrame
// delegating framer.writeSynStreamFrame
func (frame *SynStreamFrame) write(f *Framer) error {
	return f.writeSynStreamFrame(frame)
}

// Writes a frame to SynReplyFrame
// delegating framer.writeSynReplayFrame
func (frame *SynReplyFrame) write(f *Framer) error {
	return f.writeSynReplyFrame(frame)
}

// Writes a frame to RstStreamFrame
func (frame *RstStreamFrame) write(f *Framer) (err error) {
	if frame.StreamId == 0 {
		return &Error{ZeroStreamId, 0}
	}
	frame.CFHeader.version = Version
	frame.CFHeader.frameType = TypeRstStream
	frame.CFHeader.Flags = 0
	frame.CFHeader.length = 8

	// Serialize frame to Writer
	if err = writeControlFrameHeader(f.w, frame.CFHeader); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.StreamId); err != nil {
		return
	}
	if frame.Status == 0 {
		// RST_STREAM Status should not be 0
		return &Error{InvalidControlFrame, frame.StreamId}
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.Status); err != nil {
		return
	}
	return
}

// Writes a frame to SettingsFrame
func (frame *SettingsFrame) write(f *Framer) (err error) {
	frame.CFHeader.version = Version
	frame.CFHeader.frameType = TypeSettings
	frame.CFHeader.length = uint32(len(frame.FlagIdValues)*8 + 4)

	// Serialize frame to Writer
	if err = writeControlFrameHeader(f.w, frame.CFHeader); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, uint32(len(frame.FlagIdValues))); err != nil {
		return
	}
	for _, flagIdValue := range frame.FlagIdValues {
		flagId := (uint32(flagIdValue.Flag) << 24) | uint32(flagIdValue.Id)
		if err = binary.Write(f.w, binary.BigEndian, flagId); err != nil {
			return
		}
		if err = binary.Write(f.w, binary.BigEndian, flagIdValue.Value); err != nil {
			return
		}
	}
	return
}

// Writes a frame to PingFrame
func (frame *PingFrame) write(f *Framer) (err error) {
	if frame.Id == 0 {
		return &Error{ZeroStreamId, 0}
	}
	frame.CFHeader.version = Version
	frame.CFHeader.frameType = TypePing
	frame.CFHeader.Flags = 0
	frame.CFHeader.length = 4

	// Serialize frame to Writer
	if err = writeControlFrameHeader(f.w, frame.CFHeader); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.Id); err != nil {
		return
	}
	return
}

// Writes a frame to GoAwayFrame
func (frame *GoAwayFrame) write(f *Framer) (err error) {
	frame.CFHeader.version = Version
	frame.CFHeader.frameType = TypeGoAway
	frame.CFHeader.Flags = 0
	frame.CFHeader.length = 8

	// Serialize frame to Writer
	if err = writeControlFrameHeader(f.w, frame.CFHeader); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.LastGoodStreamId); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.GoAwayStatus); err != nil {
		return
	}
	return nil
}

// Writes a frame to HeadersFrame
func (frame *HeadersFrame) write(f *Framer) error {
	return f.writeHeadersFrame(frame)
}

// Writes a frame to WindowUpdateFrame
func (frame *WindowUpdateFrame) write(f *Framer) (err error) {
	frame.CFHeader.version = Version
	frame.CFHeader.frameType = TypeWindowUpdate
	frame.CFHeader.Flags = 0
	frame.CFHeader.length = 8

	// Serialize frame to Writer
	if err = writeControlFrameHeader(f.w, frame.CFHeader); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.StreamId); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.DeltaWindowSize); err != nil {
		return
	}
	return nil
}

// Writes a frame to DataFrame
func (frame *DataFrame) write(f *Framer) error {
	return f.writeDataFrame(frame)
}

// WriteFrame writes a frame.
// Delegates each frames write()
func (f *Framer) WriteFrame(frame Frame) error {
	return frame.write(f)
}

// Write Control bit 1, Version, Type, Flags, Length to buffer
func writeControlFrameHeader(w io.Writer, h ControlFrameHeader) error {
	controlBit := uint16(0x8000)
	if err := binary.Write(w, binary.BigEndian, controlBit|h.version); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, h.frameType); err != nil {
		return err
	}
	flagsAndLength := (uint32(h.Flags) << 24) | h.length
	if err := binary.Write(w, binary.BigEndian, flagsAndLength); err != nil {
		return err
	}
	return nil
}

// Write Header/Values Block to buffer
// firstly write a number of name/value pair and
// repeats length of name & name, length of value & value
func writeHeaderValueBlock(w io.Writer, h http.Header) (n int, err error) {
	n = 0
	if err = binary.Write(w, binary.BigEndian, uint32(len(h))); err != nil {
		return
	}
	n += 2
	for name, values := range h {
		if err = binary.Write(w, binary.BigEndian, uint32(len(name))); err != nil {
			return
		}
		n += 2
		name = strings.ToLower(name)
		if _, err = io.WriteString(w, name); err != nil {
			return
		}
		n += len(name)
		v := strings.Join(values, headerValueSeparator)
		if err = binary.Write(w, binary.BigEndian, uint32(len(v))); err != nil {
			return
		}
		n += 2
		if _, err = io.WriteString(w, v); err != nil {
			return
		}
		n += len(v)
	}
	return
}

// Writes a frame to SynStreamFrame
// if header compression is enable,
// writes a name/value using zlib.NewWriterLevelDict
func (f *Framer) writeSynStreamFrame(frame *SynStreamFrame) (err error) {
	if frame.StreamId == 0 {
		return &Error{ZeroStreamId, 0}
	}
	// Marshal the headers.
	var writer io.Writer = f.headerBuf
	if !f.headerCompressionDisabled {
		writer = f.headerCompressor // zlib.NewWriterLevelDict
	}
	if _, err = writeHeaderValueBlock(writer, frame.Headers); err != nil {
		return
	}
	if !f.headerCompressionDisabled {
		f.headerCompressor.Flush()
	}

	// Set ControlFrameHeader
	frame.CFHeader.version = Version
	frame.CFHeader.frameType = TypeSynStream
	frame.CFHeader.length = uint32(len(f.headerBuf.Bytes()) + 10)

	// Serialize frame to Writer
	if err = writeControlFrameHeader(f.w, frame.CFHeader); err != nil {
		return err
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.StreamId); err != nil {
		return err
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.AssociatedToStreamId); err != nil {
		return err
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.Priority<<5); err != nil {
		return err
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.Slot); err != nil {
		return err
	}
	if _, err = f.w.Write(f.headerBuf.Bytes()); err != nil {
		return err
	}
	f.headerBuf.Reset()
	return nil
}

// Writes a frame to SynReplyFrame
// if header compression is enable,
// writes a name/value using zlib.NewWriterLevelDict
func (f *Framer) writeSynReplyFrame(frame *SynReplyFrame) (err error) {
	if frame.StreamId == 0 {
		return &Error{ZeroStreamId, 0}
	}
	// Marshal the headers.
	var writer io.Writer = f.headerBuf
	if !f.headerCompressionDisabled {
		writer = f.headerCompressor // zlib.NewWriterLevelDict
	}
	if _, err = writeHeaderValueBlock(writer, frame.Headers); err != nil {
		return
	}
	if !f.headerCompressionDisabled {
		f.headerCompressor.Flush()
	}

	// Set ControlFrameHeader
	frame.CFHeader.version = Version
	frame.CFHeader.frameType = TypeSynReply
	frame.CFHeader.length = uint32(len(f.headerBuf.Bytes()) + 4)

	// Serialize frame to Writer
	if err = writeControlFrameHeader(f.w, frame.CFHeader); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.StreamId); err != nil {
		return
	}
	if _, err = f.w.Write(f.headerBuf.Bytes()); err != nil {
		return
	}
	f.headerBuf.Reset()
	return
}

// Writes a frame to HeadersFrame
// if header compression is enable,
// writes a name/value using zlib.NewWriterLevelDict
func (f *Framer) writeHeadersFrame(frame *HeadersFrame) (err error) {
	if frame.StreamId == 0 {
		return &Error{ZeroStreamId, 0}
	}
	// Marshal the headers.
	var writer io.Writer = f.headerBuf
	if !f.headerCompressionDisabled {
		writer = f.headerCompressor // zlib.NewWriterLevelDict
	}
	if _, err = writeHeaderValueBlock(writer, frame.Headers); err != nil {
		return
	}
	if !f.headerCompressionDisabled {
		f.headerCompressor.Flush()
	}

	// Set ControlFrameHeader
	frame.CFHeader.version = Version
	frame.CFHeader.frameType = TypeHeaders
	frame.CFHeader.length = uint32(len(f.headerBuf.Bytes()) + 4)

	// Serialize frame to Writer
	if err = writeControlFrameHeader(f.w, frame.CFHeader); err != nil {
		return
	}
	if err = binary.Write(f.w, binary.BigEndian, frame.StreamId); err != nil {
		return
	}
	if _, err = f.w.Write(f.headerBuf.Bytes()); err != nil {
		return
	}
	f.headerBuf.Reset()
	return
}

// Writes a frame to DataFrame
func (f *Framer) writeDataFrame(frame *DataFrame) (err error) {
	if frame.StreamId == 0 {
		return &Error{ZeroStreamId, 0}
	}
	// Validate DataFrame
	if frame.StreamId&0x80000000 != 0 || len(frame.Data) >= 0x0f000000 {
		return &Error{InvalidDataFrame, frame.StreamId}
	}

	// Serialize frame to Writer
	if err = binary.Write(f.w, binary.BigEndian, frame.StreamId); err != nil {
		return
	}
	flagsAndLength := (uint32(frame.Flags) << 24) | uint32(len(frame.Data))
	if err = binary.Write(f.w, binary.BigEndian, flagsAndLength); err != nil {
		return
	}
	if _, err = f.w.Write(frame.Data); err != nil {
		return
	}

	return nil
}
