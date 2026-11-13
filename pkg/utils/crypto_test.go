package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveKeyIsPurposeSpecific(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a, err := DeriveKey(secret, KeyPurposeCookieAuth)
	require.NoError(t, err)
	b, err := DeriveKey(secret, KeyPurposeCookieEncrypt)
	require.NoError(t, err)
	require.Len(t, a, 32)
	require.NotEqual(t, a, b)
	require.NotEqual(t, secret, a)
	_, err = DeriveKey(nil, KeyPurposeCookieAuth)
	require.Error(t, err)
}

func TestSealerRoundTripAndBinding(t *testing.T) {
	key, err := DeriveKey([]byte("secret"), KeyPurposeUpstreamTokens)
	require.NoError(t, err)
	s, err := NewSealer(key)
	require.NoError(t, err)

	sealed, err := s.Seal("refresh-token", "alice@example.com")
	require.NoError(t, err)
	require.NotContains(t, sealed, "refresh-token")

	plain, err := s.Open(sealed, "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, "refresh-token", plain)

	_, err = s.Open(sealed, "bob@example.com")
	require.Error(t, err, "bound to the user")
	_, err = s.Open("garbage", "alice@example.com")
	require.Error(t, err)
}
