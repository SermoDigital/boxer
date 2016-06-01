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
		log.Fatalln(err)
	}
}

func TestValidCrypt(t *testing.T) {
	var buf bytes.Buffer
	e := NewEncryptor(&buf, nonce, key)
	e.Write(data)
	e.Close()

	d := NewDecryptor(&buf, nonce, key)
	var buf2 bytes.Buffer
	_, err := io.Copy(&buf2, d)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, buf2.Bytes()) {
		log.Fatalf("data len == %d, buf2 len == %d", len(data), len(buf2.Bytes()))
	}
}
