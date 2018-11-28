// Courtesy https://github.com/zmap/zgrab/commit/3a144e6e866b8c96b5717ce455ad5034630e918b

package ssh

import (
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

const (
	kexAlgoDHGEXSHA256 = "diffie-hellman-group-exchange-sha256"
)

const(
	gexMinBits        uint32 = 1024
	gexMaxBits        uint32 = 8192
	gexPreferredBits  uint32 = 2048
)

// Messages
type kexDHGexGroupMsg struct {
	P *big.Int `sshtype:"31"`
	G *big.Int
}

type kexDHGexInitMsg struct {
	X *big.Int `sshtype:"32"`
}

type kexDHGexReplyMsg struct {
	HostKey   []byte `sshtype:"33"`
	Y         *big.Int
	Signature []byte
}

type kexDHGexRequestMsg struct {
	MinBits      uint32 `sshtype:"34"`
	PreferedBits uint32
	MaxBits      uint32
}

type dhGEXSHA struct {
	g, p     *big.Int
	hashFunc crypto.Hash
}

func (gex *dhGEXSHA) GetNew(keyType string) kexAlgorithm {
	switch keyType {
	case kexAlgoDHGEXSHA256:
		ret := new(dhGEXSHA)
		ret.hashFunc = crypto.SHA256
		return ret

	default:
		panic("Unimplemented GEX selected")
	}
}

func (gex *dhGEXSHA) diffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	if theirPublic.Sign() <= 0 || theirPublic.Cmp(gex.p) >= 0 {
		return nil, fmt.Errorf("ssh: DH parameter out of bounds")
	}
	return new(big.Int).Exp(theirPublic, myPrivate, gex.p), nil
}

func (gex *dhGEXSHA) Client(c packetConn, randSource io.Reader, magics *handshakeMagics) (*kexResult, error) {
	// Send GexRequest
	kexDHGexRequest := kexDHGexRequestMsg{
		MinBits:      gexMinBits,
		PreferedBits: gexPreferredBits,
		MaxBits:      gexMaxBits,
	}
	if err := c.writePacket(Marshal(&kexDHGexRequest)); err != nil {
		return nil, err
	}

	// *Receive GexGroup*
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexDHGexGroup kexDHGexGroupMsg
	if err = Unmarshal(packet, &kexDHGexGroup); err != nil {
		return nil, err
	}

	// reject if p's bit length < gexMinBits or > gexMaxBits
	if kexDHGexGroup.P.BitLen() < int(gexMinBits) || kexDHGexGroup.P.BitLen() > int(gexMaxBits) {
		return nil, fmt.Errorf("Server-generated gex p (dont't ask) is out of range (%d bits)", kexDHGexGroup.P.BitLen())
	}

	gex.p = kexDHGexGroup.P
	gex.g = kexDHGexGroup.G

	// *Send GexInit
	x, err := rand.Int(randSource, gex.p)
	if err != nil {
		return nil, err
	}
	X := new(big.Int).Exp(gex.g, x, gex.p)
	kexDHGexInit := kexDHGexInitMsg{
		X: X,
	}

	if err := c.writePacket(Marshal(&kexDHGexInit)); err != nil {
		return nil, err
	}

	// Receive GexReply
	packet, err = c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexDHGexReply kexDHGexReplyMsg
	if err = Unmarshal(packet, &kexDHGexReply); err != nil {
		return nil, err
	}

	kInt, err := gex.diffieHellman(kexDHGexReply.Y, x)
	if err != nil {
		return nil, err
	}

	h := gex.hashFunc.New()
	magics.write(h)
	writeString(h, kexDHGexReply.HostKey)
	binary.Write(h, binary.BigEndian, gexMinBits)
	binary.Write(h, binary.BigEndian, gexPreferredBits)
	binary.Write(h, binary.BigEndian, gexMaxBits)
	writeInt(h, gex.p)
	writeInt(h, gex.g)
	writeInt(h, X)
	writeInt(h, kexDHGexReply.Y)
	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	return &kexResult{
		H:         h.Sum(nil),
		K:         K,
		HostKey:   kexDHGexReply.HostKey,
		Signature: kexDHGexReply.Signature,
		Hash:      gex.hashFunc,
	}, nil
}

func (gex *dhGEXSHA) Server(c packetConn, randSource io.Reader, magics *handshakeMagics, priv Signer) (result *kexResult, err error) {
	panic("Not yet implemented")
}
