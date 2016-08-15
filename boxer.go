// Package boxer is a streaming encryption implementation, based on Adam
// Langley's article: https://www.imperialviolet.org/2014/06/27/streamingencryption.html
//
// In short, nacl/secretbox is used to seal a file in chunks, with each chunk
// being prefixed with its length. The nonce is incrementally marked so
// chunks are guaranteed to be in order. The encrypted blob is prepended with
// a header containing a version ID, the maximum chunk size, and flags. The
// flags are currently unused, but may be used in future versions.
package boxer

import (
	"encoding/binary"
	"errors"
	"io"
	"math"

	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrAlreadyClosed = errors.New("encryptor: already closed")
	ErrInvalidData   = errors.New("decryptor: encrypted message is invalid")
	ErrChunkSize     = errors.New("boxer: invalid chunk size")
)

const (
	// DefaultChunkSize is the default maximum chunk size for reading and
	// writing.
	DefaultChunkSize = 65536

	// Overhead is the number of bytes of overhead when boxing a message.
	Overhead = secretbox.Overhead

	// offset is the number of bytes used to advise the length of the
	// chunk. It should be large enough to advise the entirety of
	// the chunk.
	offset = 4

	ver1 = 1
)

func nonceKey(nonce *[16]byte, key *[32]byte) (*[24]byte, *[32]byte) {
	var n [24]byte
	copy(n[:], nonce[:])
	var k [32]byte
	copy(k[:], key[:])
	return &n, &k
}

type chunk uint32

// Encryptor is an io.WriteCloser. Writes to an Encryptor are encrypted
// and written to w.
type Encryptor struct {
	w     io.Writer // underlying writer
	nonce *[24]byte // nacl nonce, increments per chunk
	key   *[32]byte // encryption key
	in    []byte    // input buffer
	out   []byte    // encryption buffer
	size  int       // chunk size
	n     int       // end of buffer
	err   error     // last error
}

// NewEncryptor returns a new Encryptor. Writes to the returned Encryptor
// are encrypted and written to w. The size parameter dictates the maximum
// chunk size. It should be a positive integer in the range [0, 1 << 32 - 1].
// Writes will always be chunk size + Overhead.
//
// All writes will not be flushed until Close is called. Not closing an
// Encryptor will rsult in an invalid stream.
//
// Neither nonce or key are modified.
func NewEncryptorSize(w io.Writer, nonce *[16]byte, key *[32]byte, size int) (*Encryptor, error) {
	if size > math.MaxInt32 {
		return nil, ErrChunkSize
	}
	e := Encryptor{w: w, size: size}
	err := e.writeHeaders()
	if err != nil {
		return nil, err
	}
	// Save the allocations until after we've determined everything is kosher.
	e.in = make([]byte, e.size)
	e.out = make([]byte, offset+Overhead+e.size)
	e.nonce, e.key = nonceKey(nonce, key)
	return &e, nil
}

// NewEncryptor creates an Encryptor with the default chunk size.
func NewEncryptor(w io.Writer, nonce *[16]byte, key *[32]byte) *Encryptor {
	enc, _ := NewEncryptorSize(w, nonce, key, DefaultChunkSize)
	return enc
}

func (e *Encryptor) writeHeaders() error {
	_, err := e.w.Write([]byte{ver1 /* version */, 0 /* flags */})
	if err != nil {
		return err
	}
	return binary.Write(e.w, binary.LittleEndian, uint32(e.size))
}

// Writer writes an encrypted form of p to the underlying io.Writer. The
// compressed bytes are not necessarily flushed until the Encryptor is closed.
func (e *Encryptor) Write(p []byte) (n int, err error) {
	if e.err != nil {
		return 0, e.err
	}
	var m int
	for n < len(p) {
		m = copy(e.in[e.n:], p[n:])
		e.n += m
		n += m
		if e.n == e.size {
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
	binary.LittleEndian.PutUint32(e.out[0:], uint32(len(enc)))
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
	// Write out any pending data, mark the nonce, then write our EOF byte.
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
	in    []byte
	out   []byte
	size  chunk // chunk size
	err   error
	next  chunk
	last  bool
}

// NewDecryptor returns a new Decryptor. Nonce and key should be identical to
// the values originally passed to NewEncryptor.
//
// Neither nonce or key are modified.
func NewDecryptor(r io.Reader, nonce *[16]byte, key *[32]byte) (*Decryptor, error) {
	d := Decryptor{r: r}
	err := d.readHeaders()
	if err != nil {
		return nil, err
	}
	d.out = make([]byte, d.size)
	d.in = make([]byte, offset+Overhead+d.size)
	d.nonce, d.key = nonceKey(nonce, key)
	return &d, nil
}

func (d *Decryptor) readHeaders() error {
	var buf [1 /* ver */ + 1 /* flags */ + 4 /* chunk */ + 4 /* next */ + 0]byte
	_, err := io.ReadFull(d.r, buf[:])
	if err != nil {
		return err
	}
	if buf[0] != ver1 {
		return errors.New("boxer: invalid version ID")
	}
	_ = buf[1] // Future: flags.
	d.size = chunk(binary.LittleEndian.Uint32(buf[2:]))
	if d.size >= math.MaxInt32 {
		return ErrChunkSize
	}
	d.next = chunk(binary.LittleEndian.Uint32(buf[6:]))
	return nil
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
	d.next = chunk(binary.LittleEndian.Uint32(d.in[d.eb-offset:]))

	// The minimum read should be 18 bytes. The only time we'll
	// have less is the very end where our buffer looks like:
	// [ x x x x x x x x x x x x x x x x 1 ]
	//   |                             | |
	//   |_____________________________| |_ EOF byte
	//                  |
	//        16 bytes of authenticator
	if d.eb < Overhead+offset {
		d.last = true
		d.nonce[23] |= 0x80
	} else {
		d.eb -= offset
	}

	// If we're reading the last chunk it's okay to have an invalid next chunk.
	// It might be left over data from the previous read.
	if !d.last && (d.next <= 0 || d.next > d.size+Overhead) {
		return ErrInvalidData
	}

	m, ok := secretbox.Open(d.out[:0], d.in[:d.eb], d.nonce, d.key)
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
	return nil
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
