package main

import (
	"bytes"
	crypto_rand "crypto/rand"
	"crypto/sha512"
	"errors"
	"math/rand"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/jedisct1/dlog"
	"github.com/jedisct1/xsecretbox"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/salsa20/salsa"
)

const (
	NonceSize        = xsecretbox.NonceSize
	HalfNonceSize    = xsecretbox.NonceSize / 2
	TagSize          = xsecretbox.TagSize
	PublicKeySize    = 32
	QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseOverhead = len(ServerMagic) + NonceSize + TagSize
)

func pad(packet []byte, minSize int) []byte {
	packet = append(packet, 0x80)
	for len(packet) < minSize {
		packet = append(packet, 0)
	}
	return packet
}

func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, errors.New("Invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, errors.New("Invalid padding (delimiter not found)")
		}
	}
}

func ComputeSharedKey(cryptoConstruction CryptoConstruction, secretKey *[32]byte, serverPk *[32]byte, providerName *string) (sharedKey [32]byte) {
	var cfSharedKey, cfSecretKey, cfServerPk x25519.Key
	copy(cfSecretKey[:], secretKey[:])
	copy(cfServerPk[:], serverPk[:])
	if !x25519.Shared(&cfSharedKey, &cfSecretKey, &cfServerPk) {
		dlog.Criticalf("[%v] Weak public key", providerName)
	}
	copy(sharedKey[:], cfSharedKey[:])
	if cryptoConstruction == XChacha20Poly1305 {
		xsecretbox.HChaCha20(&sharedKey)
	} else {
		var zeroNonce [16]byte
		salsa.HSalsa20(&sharedKey, &zeroNonce, &sharedKey, &salsa.Sigma)
	}
	return
}

func (proxy *Proxy) Encrypt(serverInfo *ServerInfo, packet []byte, proto string) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	nonce, clientNonce := make([]byte, NonceSize), make([]byte, HalfNonceSize)
	crypto_rand.Read(clientNonce)
	copy(nonce, clientNonce)
	var publicKey *[PublicKeySize]byte
	if proxy.ephemeralKeys {
		h := sha512.New512_256()
		h.Write(clientNonce)
		h.Write(proxy.proxySecretKey[:])
		var ephSk [32]byte
		h.Sum(ephSk[:0])
		var xPublicKey [PublicKeySize]byte

		var cfxPublicKey, cfephSk x25519.Key
		copy(cfephSk[:], ephSk[:])
		x25519.KeyGen(&cfxPublicKey, &cfephSk)
		copy(xPublicKey[:], cfxPublicKey[:])

		publicKey = &xPublicKey
		xsharedKey := ComputeSharedKey(serverInfo.CryptoConstruction, &ephSk, &serverInfo.ServerPk, nil)
		sharedKey = &xsharedKey
	} else {
		sharedKey = &serverInfo.SharedKey
		publicKey = &proxy.proxyPublicKey
	}
	minQuestionSize := QueryOverhead + len(packet)
	if proto == "udp" {
		minQuestionSize = Max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
	} else {
		var xpad [1]byte
		rand.Read(xpad[:])
		minQuestionSize += int(xpad[0])
	}
	paddedLength := Min(MaxDNSUDPPacketSize, (Max(minQuestionSize, QueryOverhead)+63) & ^63)
	if QueryOverhead+len(packet)+1 > paddedLength {
		err = errors.New("Question too large; cannot be padded")
		return
	}
	encrypted = append(serverInfo.MagicQuery[:], publicKey[:]...)
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	padded := pad(packet, paddedLength-QueryOverhead)
	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		encrypted = xsecretbox.Seal(encrypted, nonce, padded, sharedKey[:])
	} else {
		var xsalsaNonce [24]byte
		copy(xsalsaNonce[:], nonce)
		encrypted = secretbox.Seal(encrypted, padded, &xsalsaNonce, sharedKey)
	}
	return
}

func (proxy *Proxy) Decrypt(serverInfo *ServerInfo, sharedKey *[32]byte, encrypted []byte, nonce []byte) ([]byte, error) {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
		len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) ||
		!bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
		return encrypted, errors.New("Invalid message size or prefix")
	}
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errors.New("Unexpected nonce")
	}
	var packet []byte
	var err error
	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		packet, err = xsecretbox.Open(nil, serverNonce, encrypted[responseHeaderLen:], sharedKey[:])
	} else {
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], serverNonce)
		var ok bool
		packet, ok = secretbox.Open(nil, encrypted[responseHeaderLen:], &xsalsaServerNonce, sharedKey)
		if !ok {
			err = errors.New("Incorrect tag")
		}
	}
	if err != nil {
		return encrypted, err
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < MinDNSPacketSize {
		return encrypted, errors.New("Incorrect padding")
	}
	return packet, nil
}
