package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadKey(t *testing.T) {
	key, err := ReadKey(SigningKey, "../../data/key.json", http.DefaultClient)
	require.NoError(t, err)

	require.NotNil(t, key)
}
