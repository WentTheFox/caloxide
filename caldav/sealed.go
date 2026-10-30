package caldav

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

// The calendar cache holds the decrypted calendar, so it is sealed on disk. The file is a
// small JSON envelope around a NaCl secretbox (XSalsa20-Poly1305: encrypted and
// authenticated, so a changed byte is detected) of the cache's JSON. The key is derived
// from the bridge password (auth.CacheKey) and exists only in memory, so the cache can be
// read only after a client has authenticated, which is when it is restored anyway. A fresh
// random nonce is used for every save. What stays visible is the calendar ID in the file
// name and roughly how big the calendar is.
const (
	sealedFormat  = "caloxide-cache"
	sealedVersion = 1
)

type sealedFile struct {
	Format  string
	Version int
	Sealed  string // base64 of nonce (24 bytes) followed by the box
}

var (
	// errNeedKey: the file is sealed and there is no key to open it with.
	errNeedKey = errors.New("the cache is encrypted and no key is available")
	// errWrongKey covers a changed bridge password and a damaged or altered file alike:
	// the authentication tag does not tell them apart, and either way the cache is not
	// used and the calendar is loaded from Proton.
	errWrongKey = errors.New("the cache cannot be decrypted (the bridge password changed, or the file is damaged)")
)

func sealCache(pc persistedCache, key *[32]byte) ([]byte, error) {
	plain, err := json.Marshal(pc)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("no randomness for the nonce: %w", err)
	}
	box := secretbox.Seal(nonce[:], plain, &nonce, key)
	return json.Marshal(sealedFile{Format: sealedFormat, Version: sealedVersion, Sealed: base64.StdEncoding.EncodeToString(box)})
}

// openCacheFile reads a cache file in either form. sealed says which it was: a file from a
// version before encryption is read as it is, and is sealed the next time it is saved.
func openCacheFile(raw []byte, key *[32]byte) (pc persistedCache, sealed bool, err error) {
	var env sealedFile
	if json.Unmarshal(raw, &env) == nil && env.Format == sealedFormat {
		if key == nil {
			return pc, true, errNeedKey
		}
		if env.Version != sealedVersion {
			return pc, true, fmt.Errorf("the cache uses format version %d, which this version does not know", env.Version)
		}
		box, err := base64.StdEncoding.DecodeString(env.Sealed)
		if err != nil || len(box) < 24+secretbox.Overhead {
			return pc, true, errWrongKey
		}
		var nonce [24]byte
		copy(nonce[:], box[:24])
		plain, ok := secretbox.Open(nil, box[24:], &nonce, key)
		if !ok {
			return pc, true, errWrongKey
		}
		if err := json.Unmarshal(plain, &pc); err != nil {
			return pc, true, fmt.Errorf("the decrypted cache is unreadable: %w", err)
		}
		return pc, true, nil
	}
	if err := json.Unmarshal(raw, &pc); err != nil {
		return pc, false, err
	}
	return pc, false, nil
}
