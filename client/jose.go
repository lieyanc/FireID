package client

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// The signature algorithms accepted. Anything else — none, the HMAC family,
// other hash sizes — is refused before a key is even looked up. RS256 and
// ES256 are what Fire ID signs with; PS256 and EdDSA cost nothing extra.
const (
	algRS256 = "RS256"
	algPS256 = "PS256"
	algES256 = "ES256"
	algEdDSA = "EdDSA"
)

// The RSA modulus sizes accepted. 1024-bit keys are factorable with a
// budget; nobody publishes them on purpose any more. Above 16384 bits a
// verification costs more than any honest key asks for, and a provider's
// key set is the one place an attacker could plant such a key.
const (
	minRSABits = 2048
	maxRSABits = 16384
)

// b64 is the base64url alphabet without padding that JOSE uses. Strict mode
// refuses encodings whose unused trailing bits are not zero, so a segment
// has exactly one valid encoding.
var b64 = base64.RawURLEncoding.Strict()

// errSignature is the one message for every signature that does not verify.
var errSignature = errors.New("signature does not verify")

// jws is a parsed compact JWS: header, payload and signature, plus the first
// two segments as sent, which is what the signature covers.
type jws struct {
	header  jwsHeader
	payload []byte
	// claims are the payload's members by exact name; parseJWS refused any
	// name that appeared twice.
	claims    map[string]json.RawMessage
	signInput []byte
	signature []byte
}

// jwsHeader is what the verifier reads from a JOSE header: alg and kid pick
// the key, typ tells the token kinds apart.
type jwsHeader struct {
	Alg string
	Kid string
	Typ string
}

// parseJWS splits and decodes a compact JWS without verifying it. It refuses
// what a verifier would otherwise have to think about: a segment count other
// than three, data that is not base64url, an alg outside the allowlist, a
// crit header (no extension is understood, so none can be honoured), a
// header or payload that is not a JSON object, and a member name that
// appears twice. Key-carrying headers — jku, jwk, x5u, x5c — are ignored: the
// key always comes from the provider's JWKS.
func parseJWS(raw string) (*jws, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed header")
	}
	header, err := parseHeader(headerJSON)
	if err != nil {
		return nil, err
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed payload")
	}
	claims, err := decodeObject(payload)
	if err != nil {
		return nil, fmt.Errorf("payload %v", err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return nil, errors.New("malformed signature")
	}
	return &jws{
		header:    header,
		payload:   payload,
		claims:    claims,
		signInput: []byte(parts[0] + "." + parts[1]),
		signature: sig,
	}, nil
}

// parseHeader reads a JOSE header by exact member name (RFC 7515 section 4):
// alg must be on the allowlist, kid and typ must be strings when present,
// and a crit member is refused whatever its value. Any other member,
// including one that differs from these only in case, is passed over.
func parseHeader(data []byte) (jwsHeader, error) {
	var h jwsHeader
	members, err := decodeObject(data)
	if err != nil {
		return h, fmt.Errorf("header %v", err)
	}
	for name, dst := range map[string]*string{"alg": &h.Alg, "kid": &h.Kid, "typ": &h.Typ} {
		if raw, ok := members[name]; ok && json.Unmarshal(raw, dst) != nil {
			return h, fmt.Errorf("header %s is not a string", name)
		}
	}
	switch h.Alg {
	case algRS256, algPS256, algES256, algEdDSA:
	default:
		return h, fmt.Errorf("alg %q is not accepted", h.Alg)
	}
	if _, ok := members["crit"]; ok {
		return h, errors.New("crit header is not supported")
	}
	return h, nil
}

// errNotObject is decodeObject's answer to anything but one JSON object.
var errNotObject = errors.New("is not a JSON object")

// decodeObject reads data as exactly one JSON object and returns its members
// by name as written: no case folding, and a name that appears twice is an
// error, as RFC 7515 section 4 and RFC 7519 section 4 allow. Both rules
// exist so that two readers of the same token cannot disagree about what a
// member says — encoding/json would otherwise match "ALG" to alg when
// filling a struct and keep the last of two "alg" members.
func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errNotObject
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errNotObject
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errNotObject
		}
		if _, dup := members[name]; dup {
			return nil, fmt.Errorf("has member %q twice", name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, errNotObject
		}
		members[name] = value
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errNotObject
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errNotObject
	}
	return members, nil
}

// hashForAlg is the hash an alg is defined with, which is also what at_hash
// is computed with (OpenID Connect Core 1.0 section 3.1.3.6). Ed25519
// signs with SHA-512.
func hashForAlg(alg string) crypto.Hash {
	if alg == algEdDSA {
		return crypto.SHA512
	}
	return crypto.SHA256
}

// jwk is one public key from the provider's key set.
type jwk struct {
	kid string
	alg string // the alg the JWK states, or empty
	key crypto.PublicKey
}

// rawJWK is the wire form of a key (RFC 7517, RFC 7518 section 6, RFC 8037).
type rawJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWKS reads a JWK Set. Keys that are not for signing, of a type not
// supported, or malformed are left out rather than failing the whole set:
// a token that needs one of them fails with an unknown key ID, which says
// what is wrong without blocking the keys that are fine.
func parseJWKS(data []byte) ([]*jwk, error) {
	var doc struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, errors.New("not a JWK set")
	}
	keys := make([]*jwk, 0, len(doc.Keys))
	for _, r := range doc.Keys {
		if r.Use != "" && r.Use != "sig" {
			continue
		}
		key, err := r.publicKey()
		if err != nil {
			continue
		}
		keys = append(keys, &jwk{kid: r.Kid, alg: r.Alg, key: key})
	}
	return keys, nil
}

// publicKey turns the wire form into a key, checking what the verifier
// relies on: the RSA modulus size, the curve, and that an EC point is on it.
func (r rawJWK) publicKey() (crypto.PublicKey, error) {
	switch r.Kty {
	case "RSA":
		n, err := b64.DecodeString(r.N)
		if err != nil {
			return nil, err
		}
		e, err := b64.DecodeString(r.E)
		if err != nil {
			return nil, err
		}
		modulus := new(big.Int).SetBytes(n)
		if bits := modulus.BitLen(); bits < minRSABits || bits > maxRSABits {
			return nil, fmt.Errorf("RSA key of %d bits refused", bits)
		}
		exp := new(big.Int).SetBytes(e)
		if exp.BitLen() > 31 || exp.Cmp(big.NewInt(2)) < 0 {
			return nil, errors.New("RSA exponent out of range")
		}
		return &rsa.PublicKey{N: modulus, E: int(exp.Int64())}, nil
	case "EC":
		if r.Crv != "P-256" {
			return nil, fmt.Errorf("curve %q is not supported", r.Crv)
		}
		x, err := b64.DecodeString(r.X)
		if err != nil {
			return nil, err
		}
		y, err := b64.DecodeString(r.Y)
		if err != nil {
			return nil, err
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("malformed P-256 point")
		}
		point := append(append([]byte{4}, x...), y...)
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	case "OKP":
		if r.Crv != "Ed25519" {
			return nil, fmt.Errorf("curve %q is not supported", r.Crv)
		}
		x, err := b64.DecodeString(r.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("malformed Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("key type %q is not supported", r.Kty)
	}
}

// verify checks sig over input with this key under alg. The alg must equal
// what the JWK states when it states one, and must fit the key's type: a
// token cannot pick a weaker algorithm for a key than the one it was
// published for, and an RSA key is never used as an EC one or the reverse.
func (k *jwk) verify(alg string, input, sig []byte) error {
	if k.alg != "" && k.alg != alg {
		return fmt.Errorf("alg %s does not match the key's %s", alg, k.alg)
	}
	switch key := k.key.(type) {
	case *rsa.PublicKey:
		h := sha256.Sum256(input)
		switch alg {
		case algRS256:
			if rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig) != nil {
				return errSignature
			}
			return nil
		case algPS256:
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
			if rsa.VerifyPSS(key, crypto.SHA256, h[:], sig, opts) != nil {
				return errSignature
			}
			return nil
		}
	case *ecdsa.PublicKey:
		if alg == algES256 {
			// JWS carries r||s as two fixed-size integers, not DER.
			if len(sig) != 64 {
				return errors.New("malformed ES256 signature")
			}
			h := sha256.Sum256(input)
			r := new(big.Int).SetBytes(sig[:32])
			s := new(big.Int).SetBytes(sig[32:])
			if !ecdsa.Verify(key, h[:], r, s) {
				return errSignature
			}
			return nil
		}
	case ed25519.PublicKey:
		if alg == algEdDSA {
			if !ed25519.Verify(key, input, sig) {
				return errSignature
			}
			return nil
		}
	}
	return fmt.Errorf("alg %s does not fit the key", alg)
}

// leftHalfHash is the at_hash / c_hash construction: the left half of the
// hash of value, base64url-encoded (OpenID Connect Core 1.0 section 3.1.3.6).
func leftHalfHash(alg, value string) string {
	var sum []byte
	switch hashForAlg(alg) {
	case crypto.SHA512:
		s := sha512.Sum512([]byte(value))
		sum = s[:]
	default:
		s := sha256.Sum256([]byte(value))
		sum = s[:]
	}
	return b64.EncodeToString(sum[:len(sum)/2])
}
