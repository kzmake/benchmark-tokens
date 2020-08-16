package benchmark

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	paseto "github.com/o1egl/paseto/v2"
)

func Benchmark_Paseto_V2_Sign(b *testing.B) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)

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
			t := paseto.JSONToken{}
			for k, v := range c.payload {
				t.Set(k, v)
			}

			const footer = "bar"

			v2 := paseto.NewV2()

			if _, err := v2.Sign(key, t, footer); err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = v2.Sign(key, t, footer)
			}
		})
	}
}

func Benchmark_Paseto_V2_Verify(b *testing.B) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

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
			t := paseto.JSONToken{}
			for k, v := range c.payload {
				t.Set(k, v)
			}

			v2 := paseto.NewV2()

			token, _ := v2.Sign(privateKey, t, "bar")

			var claims paseto.JSONToken
			var footer string

			if err := v2.Verify(token, publicKey, &claims, &footer); err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = v2.Verify(token, publicKey, &claims, &footer)
			}
		})
	}
}
