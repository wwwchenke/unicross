package lpr

import (
	"encoding/binary"
	"fmt"
)

func (p *PublicKey) Serialize(qMax int32) []byte {
	c := &Ciphertext{
		CT0: p.PK0,
		CT1: p.PK1,
	}
	return c.Serialize(qMax)
}

func (p *PublicKey) Deserialize(data []byte, D, qMax int32) error {
	c := new(Ciphertext)
	err := c.Deserialize(data, D, qMax)
	if err != nil {
		return err
	}
	p.PK0 = c.CT0
	p.PK1 = c.CT1
	return nil
}

func (c *Ciphertext) Serialize(qMax int32) []byte {
	if qMax <= 65536 {
		size := len(c.CT0) * 2 * 2
		data := make([]byte, size)
		offset := 0
		for _, ct := range c.CT0 {
			binary.BigEndian.PutUint16(data[offset:], uint16(ct))
			offset += 2
		}
		for _, ct := range c.CT1 {
			binary.BigEndian.PutUint16(data[offset:], uint16(ct))
			offset += 2
		}
		return data
	} else {
		size := len(c.CT0) * 2 * 4
		data := make([]byte, size)
		offset := 0
		for _, ct := range c.CT0 {
			binary.BigEndian.PutUint32(data[offset:], uint32(ct))
			offset += 4
		}
		for _, ct := range c.CT1 {
			binary.BigEndian.PutUint32(data[offset:], uint32(ct))
			offset += 4
		}
		return data
	}
}

func (c *Ciphertext) Deserialize(data []byte, D, qMax int32) (err error) {
	defer func() {
		fatal := recover()
		if fatal != nil {
			err = fmt.Errorf("Deserialize error\n")
		}
	}()
	c.CT0 = make([]int32, D)
	c.CT1 = make([]int32, D)
	if qMax <= 65536 {
		offset := 0
		for i := 0; i < int(D); i++ {
			c.CT0[i] = int32(binary.BigEndian.Uint16(data[offset:]))
			if c.CT0[i] >= qMax/2 {
				c.CT0[i] -= qMax
			} else if c.CT0[i] < -qMax/2 {
				c.CT0[i] += qMax / 2
			}

			offset += 2
		}
		for i := 0; i < int(D); i++ {
			c.CT1[i] = int32(binary.BigEndian.Uint16(data[offset:]))
			if c.CT1[i] >= qMax/2 {
				c.CT1[i] -= qMax
			} else if c.CT1[i] < -qMax/2 {
				c.CT1[i] += qMax / 2
			}
			offset += 2
		}

	} else {
		offset := 0
		for i := 0; i < int(D); i++ {
			c.CT0[i] = int32(binary.BigEndian.Uint32(data[offset:]))
			if c.CT0[i] >= qMax/2 {
				c.CT0[i] -= qMax
			} else if c.CT0[i] < -qMax/2 {
				c.CT0[i] += qMax / 2
			}
			offset += 4
		}
		for i := 0; i < int(D); i++ {
			c.CT1[i] = int32(binary.BigEndian.Uint32(data[offset:]))
			if c.CT1[i] >= qMax/2 {
				c.CT1[i] -= qMax
			} else if c.CT1[i] < -qMax/2 {
				c.CT1[i] += qMax / 2
			}
			offset += 4
		}
	}
	err = nil
	return
}
