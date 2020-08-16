package benchmark

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

func Benchmark_JWT_ES512_Sign(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	cases := []struct {
		name    string
		payload map[string]interface{}
	}{
		{"len10", map[string]interface{}{"fo": "o"}},
		{"len100", map[string]interface{}{"fo": "o" + strings.Repeat("a", 90)}},
		{"len1000", map[string]interface{}{"fo": "o" + strings.Repeat("a", 990)}},
		{"len10000", map[string]interface{}{"fo": "o" + strings.Repeat("a", 9990)}},
		{"len100000", map[string]interface{}{"fo": "o" + strings.Repeat("a", 99990)}},
	}
	for _, c := range cases {
		c := c

		b.Run(c.name, func(b *testing.B) {
			t := jwt.New()
			for k, v := range c.payload {
				if err := t.Set(k, v); err != nil {
					panic(err)
				}
			}

			if _, err := jwt.Sign(t, jwa.ES512, key); err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = jwt.Sign(t, jwa.ES512, key)
			}
		})
	}
}

func Benchmark_JWT_ES512_Verify(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	cases := []struct {
		name    string
		payload map[string]interface{}
	}{
		{"len10", map[string]interface{}{"fo": "o"}},
		{"len100", map[string]interface{}{"fo": "o" + strings.Repeat("a", 90)}},
		{"len1000", map[string]interface{}{"fo": "o" + strings.Repeat("a", 990)}},
		{"len10000", map[string]interface{}{"fo": "o" + strings.Repeat("a", 9990)}},
		{"len100000", map[string]interface{}{"fo": "o" + strings.Repeat("a", 99990)}},
	}
	for _, c := range cases {
		c := c

		b.Run(c.name, func(b *testing.B) {
			t := jwt.New()
			for k, v := range c.payload {
				if err := t.Set(k, v); err != nil {
					panic(err)
				}
			}

			buf, _ := jwt.Sign(t, jwa.ES512, key)
			token := bytes.NewReader(buf)

			if _, err := jwt.ParseVerify(token, jwa.ES512, &key.PublicKey); err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = jwt.ParseVerify(token, jwa.ES512, &key.PublicKey)
			}
		})
	}
}
