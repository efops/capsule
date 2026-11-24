package main

import (
	"archive/tar"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// The encrypted rootfs is a tar stream cut into AES-256-GCM chunks. Each
// chunk's header (length, plus a flag on the last one) is authenticated, so
// chunks cannot be reordered, dropped or cut short.
const (
	encMagic  = "CAPSULE-ENC-1\n"
	chunkSize = 64 << 10
	lastChunk = 1 << 31
)

type chunkWriter struct {
	aead cipher.AEAD
	w    io.Writer
	buf  []byte
	n    uint64
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		room := chunkSize - len(c.buf)
		if room == 0 {
			if err := c.flush(false); err != nil {
				return 0, err
			}
			continue
		}
		take := min(room, len(p))
		c.buf = append(c.buf, p[:take]...)
		p = p[take:]
	}
	return total, nil
}

func (c *chunkWriter) flush(last bool) error {
	header := uint32(len(c.buf) + c.aead.Overhead())
	if last {
		header |= lastChunk
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], header)
	nonce := make([]byte, c.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[4:], c.n)
	c.n++
	if _, err := c.w.Write(head[:]); err != nil {
		return err
	}
	_, err := c.w.Write(c.aead.Seal(nil, nonce, c.buf, head[:]))
	c.buf = c.buf[:0]
	return err
}

type chunkReader struct {
	aead cipher.AEAD
	r    io.Reader
	buf  []byte
	n    uint64
	done bool
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if c.done {
			return 0, io.EOF
		}
		var head [4]byte
		if _, err := io.ReadFull(c.r, head[:]); err != nil {
			return 0, errors.New("encrypted rootfs is cut short")
		}
		header := binary.BigEndian.Uint32(head[:])
		size := header &^ lastChunk
		if size > chunkSize+uint32(c.aead.Overhead()) {
			return 0, errors.New("encrypted rootfs is corrupt")
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(c.r, sealed); err != nil {
			return 0, errors.New("encrypted rootfs is cut short")
		}
		nonce := make([]byte, c.aead.NonceSize())
		binary.BigEndian.PutUint64(nonce[4:], c.n)
		c.n++
		plain, err := c.aead.Open(nil, nonce, sealed, head[:])
		if err != nil {
			return 0, errors.New("encrypted rootfs does not decrypt with this host's key")
		}
		c.buf, c.done = plain, header&lastChunk != 0
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// encryptTree writes root as an encrypted archive.
func encryptTree(root string, out io.Writer, key []byte) error {
	aead, err := newGCM(key)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(out, encMagic); err != nil {
		return err
	}
	cw := &chunkWriter{aead: aead, w: out}
	tw := tar.NewWriter(cw)
	if err := packTree(tw, root, ""); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return cw.flush(true)
}

// decryptTree unpacks an encrypted archive into dst, which must not exist.
// The caller still checks the result against the sealed hash.
func decryptTree(in io.Reader, key []byte, dst string) error {
	aead, err := newGCM(key)
	if err != nil {
		return err
	}
	magic := make([]byte, len(encMagic))
	if _, err := io.ReadFull(in, magic); err != nil || string(magic) != encMagic {
		return errors.New("rootfs.enc is not an encrypted rootfs")
	}
	_, err = unpackTar(tar.NewReader(&chunkReader{aead: aead, r: in}), dst, true)
	return err
}
