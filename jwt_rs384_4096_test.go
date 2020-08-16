package benchmark

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

func Benchmark_JWT_RS384_4096bits_Sign(b *testing.B) {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)

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

			if _, err := jwt.Sign(t, jwa.RS384, key); err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = jwt.Sign(t, jwa.RS384, key)
			}
		})
	}
}

func Benchmark_JWT_RS384_4096bits_Verify(b *testing.B) {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)

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

			buf, _ := jwt.Sign(t, jwa.RS384, key)
			token := bytes.NewReader(buf)

			if _, err := jwt.ParseVerify(token, jwa.RS384, &key.PublicKey); err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = jwt.ParseVerify(token, jwa.RS384, &key.PublicKey)
			}
		})
	}
}
