// Package boxer is an implementation of agl's article:
// https://www.imperialviolet.org/2014/06/27/streamingencryption.html
package boxer

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrAlreadyClosed = errors.New("encryptor: already closed")
	ErrInvalidData   = errors.New("decryptor: encrypted message is invalid")
)

const (
	// chunkSize is the maximum chunk size for reading and writing.
	chunkSize = 65536 //16384

	// offset is the number of bytes used to advise the length of the
	// chunk. It should be large enough to advise the entirety of chunkSize.
	// Keep this in size with the number of bytes in chunk.
	offset = 4

	tag = secretbox.Overhead
)

type chunk uint32

// Encryptor is an io.WriteCloser. Writes to an Encryptor are encrypted
// and written to w.
type Encryptor struct {
	w     io.Writer                      // underlying writer
	nonce *[24]byte                      // nacl nonce, increments per chunk
	key   *[32]byte                      // encryption key
	in    [chunkSize]byte                // input buffer
	out   [offset + tag + chunkSize]byte // encryption buffer
	n     int                            // end of buffer
	err   error                          // last error
}

// NewEncryptor returns a new Sncryptor. Writes to the returned Encryptor
// are encrypted and written to w.
//
// All writes will not be flushed until Close is called, resulting in an
// invalid stream.
//
// Neither nonce or key are modified.
func NewEncryptor(w io.Writer, nonce *[16]byte, key *[32]byte) *Encryptor {
	var n [24]byte
	copy(n[:], nonce[:])

	var k [32]byte
	copy(k[:], key[:])
	return &Encryptor{
		w:     w,
		key:   &k,
		nonce: &n,
	}
}

// Writer writes an encrypted form of p to the underlying io.Writer.
// The compressed bytes are not necessarily flushed into the Encryptor
// is closed.
func (e *Encryptor) Write(p []byte) (n int, err error) {
	if e.err != nil {
		return 0, e.err
	}
	var m int
	for n < len(p) {
		m = copy(e.in[e.n:], p[n:])
		e.n += m
		n += m
		if e.n == chunkSize {
			err := e.flush()
			if err != nil {
				return n, err
			}
		}
	}
	return n, e.err
}

func (e *Encryptor) flush() error {
	if e.err != nil {
		return e.err
	}
	enc := secretbox.Seal(e.out[offset:offset], e.in[:e.n], e.nonce, e.key)
	e.out[0] = byte(len(enc))
	e.out[1] = byte(len(enc) >> 8)
	e.out[2] = byte(len(enc) >> 16)
	e.out[3] = byte(len(enc) >> 24)
	_, e.err = e.w.Write(e.out[:offset+len(enc)])
	e.n = 0
	incrCounter(e.nonce)
	return e.err
}

// Close closes the Encryptor, flushing any unwritten data to the underlying
// io.Writer but does not close the underlying io.Writer.
func (e *Encryptor) Close() (err error) {
	if e.err == ErrAlreadyClosed {
		return ErrAlreadyClosed
	}
	// Write out any pending data, mark the nonce, and then write our EOF
	// byte.
	e.flush()
	e.nonce[23] |= 0x80
	_, err = e.Write([]byte{1})
	e.flush()

	for i := range e.in {
		e.in[i] = 0
	}
	for i := range e.out {
		e.out[i] = 0
	}
	for i := range e.key {
		e.key[i] = 0
	}
	for i := range e.nonce {
		e.nonce[i] = 0
	}
	e.err = ErrAlreadyClosed
	return err
}

func incrCounter(nonce *[24]byte) {
	for i := 16; i < 24; i++ {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// Decryptor is an io.ReadCloser that reads encrypted data written by an
// Encryptor.
type Decryptor struct {
	r     io.Reader
	nonce *[24]byte
	key   *[32]byte
	rp    int // read position
	eb    int // end of chunk, meaning depends on part of code
	in    [offset + tag + chunkSize]byte
	out   [chunkSize]byte
	err   error
	next  chunk
	last  bool
}

// NewDecryptor returns a new Decryptor. Nonce and key should be identical to the
// values originally passed to NewEncryptor.
//
// Neither nonce or key are modified.
func NewDecryptor(r io.Reader, nonce *[16]byte, key *[32]byte) *Decryptor {
	var n [24]byte
	copy(n[:], nonce[:])

	var k [32]byte
	copy(k[:], key[:])
	return &Decryptor{
		r:     r,
		key:   &k,
		nonce: &n,
	}
}

// Read implements io.Reader.
func (d *Decryptor) Read(p []byte) (n int, err error) {
	if d.err != nil || len(p) == 0 {
		return 0, d.err
	}
	var m int
	for n < len(p) {
		if d.rp >= d.eb {
			d.err = d.fill()
			if d.err != nil {
				return n, d.err
			}
		}
		m = copy(p[n:], d.out[d.rp:d.eb])
		d.rp += m
		n += m
	}
	return n, nil
}

func (d *Decryptor) fill() (err error) {
	if d.err != nil {
		return d.err
	}

	d.eb, err = d.r.Read(d.in[:d.next+offset])
	if err != nil {
		return err
	}

	d.rp = 0
	d.next = chunk(d.in[d.eb-offset]) | chunk(d.in[d.eb-offset+1])<<8 |
		chunk(d.in[d.eb-offset+2])<<16 | chunk(d.in[d.eb-offset+3])<<24

	// d.eb == offset only on first read because d.next == 0, so d.next +
	// offset = offset
	if d.eb == offset {
		return d.fill()
	}

	// The minimum read should be 18 bytes. The only time we'll
	// have less is the very end where our buffer looks like:
	// [ x x x x x x x x x x x x x x x x 1 ]
	//   |                             | |
	//   |_____________________________| |_ EOF byte
	//                  |
	//        16 bytes of authenticator
	if d.eb < tag+offset {
		d.last = true
		d.nonce[23] |= 0x80
	} else {
		d.eb -= offset
	}

	// If we're reading the last chunk it's okay to have an invalid next
	// chunk. It might be left over data from the previous read.
	if !d.last && (d.next <= 0 || d.next > chunkSize+tag) {
		return ErrInvalidData
	}

	m, ok := secretbox.Open(d.out[:0], d.in[:d.eb], d.nonce, d.key)
	if !ok {
		fmt.Println("not ok")
	}
	if !ok {
		return ErrInvalidData
	}
	d.eb = len(m)
	if d.last {
		if d.out[0] != 1 {
			return ErrInvalidData
		}
		return io.EOF
	}
	incrCounter(d.nonce)
	return err
}

// Close closes the Decryptor but does not close the underlying io.Reader.
func (d *Decryptor) Close() error {
	if d.err == ErrAlreadyClosed {
		return ErrAlreadyClosed
	}
	for i := range d.in {
		d.in[i] = 0
	}
	for i := range d.out {
		d.out[i] = 0
	}
	for i := range d.key {
		d.key[i] = 0
	}
	for i := range d.nonce {
		d.nonce[i] = 0
	}
	d.err = ErrAlreadyClosed
	return nil
}
