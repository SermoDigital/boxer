package boxer

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"testing"
)

var (
	nonce = &[16]byte{}
	key   = &[32]byte{}
	data  []byte
)

func init() {
	log.SetFlags(log.Llongfile | log.LstdFlags)
	var err error
	data, err = ioutil.ReadFile("/usr/share/dict/american-english")
	if err != nil {
		data = []byte("hello, world!")
	}
}

func testCrypt(t *testing.T, e *Encryptor, r io.Reader, data []byte) {
	e.Write(data)
	e.Close()

	d, err := NewDecryptor(r, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	var buf2 bytes.Buffer
	_, err = io.Copy(&buf2, d)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, buf2.Bytes()) {
		log.Fatalf("data len == %d, buf2 len == %d",
			len(data), len(buf2.Bytes()))
	}
}

func TestValidCrypt(t *testing.T) {
	var buf bytes.Buffer
	testCrypt(t, NewEncryptor(&buf, nonce, key), &buf, data)
}

func TestValidCryptSize(t *testing.T) {
	var buf bytes.Buffer
	e, err := NewEncryptorSize(&buf, nonce, key, 12)
	if err != nil {
		t.Fatal(err)
	}
	testCrypt(t, e, &buf, data)
}

func TestInvalidSize(t *testing.T) {
	_, err := NewEncryptorSize(nil, nonce, key, 1<<63-1)
	if err == nil {
		t.Fatal("wanted err != nil, got err == nil")
	}
}
