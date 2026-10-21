package client

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseJWSRejects(t *testing.T) {
	k := newSigningKey(t, "k1", algES256)
	good := k.sign(t, nil, map[string]any{"sub": "1"})
	parts := strings.Split(good, ".")

	hmacToken := func() string {
		h := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"k1"}`))
		p := b64.EncodeToString([]byte(`{"sub":"1"}`))
		mac := hmac.New(sha256.New, []byte("key"))
		mac.Write([]byte(h + "." + p))
		return h + "." + p + "." + b64.EncodeToString(mac.Sum(nil))
	}
	withHeader := func(hdr string) string {
		return signSegments(t, k, b64.EncodeToString([]byte(hdr)), parts[1])
	}

	cases := map[string]struct {
		raw  string
		want string
	}{
		"two segments":   {parts[0] + "." + parts[1], "not a compact JWS"},
		"four segments":  {good + ".x", "not a compact JWS"},
		"bad header b64": {tamperSegment(good, 0, "!!"), "malformed header"},
		"padded b64":     {tamperSegment(good, 1, parts[1]+"="), "malformed payload"},
		"empty sig":      {parts[0] + "." + parts[1] + ".", "malformed signature"},
		"alg none": {
			b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + ".x", `alg "none"`,
		},
		"alg HS256":  {hmacToken(), `alg "HS256"`},
		"alg RS512":  {withHeader(`{"alg":"RS512","kid":"k1"}`), `alg "RS512"`},
		"crit":       {withHeader(`{"alg":"ES256","kid":"k1","crit":["exp"],"exp":1}`), "crit"},
		"crit empty": {withHeader(`{"alg":"ES256","kid":"k1","crit":[]}`), "crit"},
		"crit null":  {withHeader(`{"alg":"ES256","kid":"k1","crit":null}`), "crit"},
		// Member names are exact and unique: ALG does not stand in for alg,
		// and a second alg — however it is escaped — is refused rather than
		// letting one reader see the first and another the last.
		"alg shadowed by ALG": {withHeader(`{"alg":"none","ALG":"ES256","kid":"k1"}`), `alg "none"`},
		"ALG only":            {withHeader(`{"ALG":"ES256","kid":"k1"}`), `alg ""`},
		"alg twice":           {withHeader(`{"alg":"ES256","kid":"k1","alg":"none"}`), `header has member "alg" twice`},
		"alg twice escaped":   {withHeader(`{"alg":"ES256","kid":"k1","al\u0067":"none"}`), `header has member "alg" twice`},
		"kid number":          {withHeader(`{"alg":"ES256","kid":1}`), "kid is not a string"},
		"typ number":          {withHeader(`{"alg":"ES256","kid":"k1","typ":1}`), "typ is not a string"},
		"header trailing data": {
			signSegments(t, k, b64.EncodeToString([]byte(`{"alg":"ES256","kid":"k1"}{}`)), parts[1]), "header is not a JSON object",
		},
		"payload claim twice": {
			signSegments(t, k, parts[0], b64.EncodeToString([]byte(`{"sub":"1","sub":"2"}`))), `payload has member "sub" twice`,
		},
		"header array": {
			signSegments(t, k, b64.EncodeToString([]byte(`[1]`)), parts[1]), "header is not a JSON object",
		},
		"header null": {
			signSegments(t, k, b64.EncodeToString([]byte(`null`)), parts[1]), "header is not a JSON object",
		},
		"payload array": {
			signSegments(t, k, parts[0], b64.EncodeToString([]byte(`["a"]`))), "payload is not a JSON object",
		},
		"payload null": {
			signSegments(t, k, parts[0], b64.EncodeToString([]byte(`null`))), "payload is not a JSON object",
		},
		"payload text": {
			signSegments(t, k, parts[0], b64.EncodeToString([]byte(`hello`))), "payload is not a JSON object",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseJWS(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}

	// The key-carrying headers are parsed past, never acted on.
	tok, err := parseJWS(withHeader(`{"alg":"ES256","kid":"k1","jku":"https://evil.test/keys","jwk":{"kty":"EC"},"x5u":"https://evil.test/c"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tok.header.Alg != algES256 || tok.header.Kid != "k1" {
		t.Fatalf("header %+v", tok.header)
	}
	// Members that differ from the known ones only in case are unknown
	// members, passed over like any other.
	tok, err = parseJWS(withHeader(`{"alg":"ES256","kid":"k1","CRIT":["x"],"TYP":"logout+jwt"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tok.header.Typ != "" {
		t.Fatalf("TYP read as typ: %+v", tok.header)
	}
}

func TestRSAKeySize(t *testing.T) {
	e := b64.EncodeToString([]byte{1, 0, 1})
	modulus := func(bits int) string {
		n := make([]byte, (bits+7)/8)
		n[0] = 1 << uint((bits-1)%8)
		return b64.EncodeToString(n)
	}
	for bits, ok := range map[int]bool{2047: false, 2048: true, 4096: true, 16384: true, 16385: false} {
		_, err := rawJWK{Kty: "RSA", N: modulus(bits), E: e}.publicKey()
		if (err == nil) != ok {
			t.Errorf("%d-bit modulus: accepted %v, err %v", bits, err == nil, err)
		}
	}
}

func TestParseJWKS(t *testing.T) {
	rsaKey := newSigningKey(t, "r", algRS256)
	ecKey := newSigningKey(t, "e", algES256)
	edKey := newSigningKey(t, "d", algEdDSA)

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallJWK := (&signingKey{kid: "small", alg: algRS256, priv: small}).jwk()
	ecJWK := ecKey.jwk()
	offCurve := map[string]any{}
	for k, v := range ecJWK {
		offCurve[k] = v
	}
	offCurve["kid"] = "off"
	offCurve["y"] = b64.EncodeToString(make([]byte, 32))
	encKey := map[string]any{"kty": "RSA", "kid": "enc", "use": "enc", "n": rsaKey.jwk()["n"], "e": "AQAB"}
	oct := map[string]any{"kty": "oct", "kid": "sym", "k": "AAAA"}
	p384 := map[string]any{"kty": "EC", "kid": "p384", "crv": "P-384", "x": ecJWK["x"], "y": ecJWK["y"]}
	noKid := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": edKey.jwk()["x"]}

	doc, err := json.Marshal(map[string]any{"keys": []map[string]any{
		rsaKey.jwk(), ecJWK, edKey.jwk(), smallJWK, offCurve, encKey, oct, p384, noKid,
	}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := parseJWKS(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, k := range keys {
		got[k.kid] = true
	}
	for _, kid := range []string{"r", "e", "d", ""} {
		if !got[kid] {
			t.Errorf("kid %q missing from %v", kid, got)
		}
	}
	for _, kid := range []string{"small", "off", "enc", "sym", "p384"} {
		if got[kid] {
			t.Errorf("kid %q should have been left out", kid)
		}
	}

	if _, err := parseJWKS([]byte(`[]`)); err == nil {
		t.Error("an array is not a JWK set")
	}
}

func TestJWKVerifyBindsAlgToKey(t *testing.T) {
	rsaKey := newSigningKey(t, "r", algRS256)
	ecKey := newSigningKey(t, "e", algES256)
	input := []byte("a.b")

	// The key states RS256; a PS256 signature with the same RSA key is
	// refused for the stated alg, not for its validity.
	ps := &signingKey{kid: "r", alg: algPS256, priv: rsaKey.priv}
	psSig := strings.Split(signSegments(t, ps, "a", "b"), ".")[2]
	sig, _ := b64.DecodeString(psSig)
	rsaJWK := &jwk{kid: "r", alg: algRS256, key: rsaKey.priv.Public()}
	if err := rsaJWK.verify(algPS256, input, sig); err == nil || !strings.Contains(err.Error(), "does not match the key's") {
		t.Errorf("PS256 against an RS256 JWK: %v", err)
	}
	// Without a stated alg, PS256 fits an RSA key.
	rsaAny := &jwk{kid: "r", key: rsaKey.priv.Public()}
	if err := rsaAny.verify(algPS256, input, sig); err != nil {
		t.Errorf("PS256 against an RSA key without alg: %v", err)
	}
	// RS256 never fits an EC key, whatever the signature.
	ecAny := &jwk{kid: "e", key: ecKey.priv.Public()}
	if err := ecAny.verify(algRS256, input, sig); err == nil || !strings.Contains(err.Error(), "does not fit") {
		t.Errorf("RS256 against an EC key: %v", err)
	}
	// A DER-encoded ECDSA signature is the wrong shape.
	if err := ecAny.verify(algES256, input, make([]byte, 70)); err == nil || !strings.Contains(err.Error(), "malformed ES256") {
		t.Errorf("70-byte ES256 signature: %v", err)
	}
}

func TestLeftHalfHash(t *testing.T) {
	// OpenID Connect Core 1.0 section A.3 example: at_hash of the access token "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y".
	got := leftHalfHash(algRS256, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y")
	if want := "77QmUPtjPfzWtF2AnpK9RQ"; got != want {
		t.Errorf("at_hash = %s, want %s", got, want)
	}
	if a, b := leftHalfHash(algEdDSA, "x"), leftHalfHash(algES256, "x"); a == b {
		t.Error("EdDSA must hash with SHA-512, not SHA-256")
	}
}
