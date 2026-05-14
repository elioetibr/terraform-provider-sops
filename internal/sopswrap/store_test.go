package sopswrap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

func TestStoreFor_KnownFormats(t *testing.T) {
	t.Parallel()
	for _, f := range []sopswrap.Format{
		sopswrap.FormatYAML,
		sopswrap.FormatJSON,
		sopswrap.FormatDotenv,
		sopswrap.FormatINI,
		sopswrap.FormatBinary,
	} {
		f := f
		t.Run(string(f), func(t *testing.T) {
			t.Parallel()
			s, err := sopswrap.StoreFor(f)
			require.NoError(t, err)
			require.NotNil(t, s)
		})
	}
}

func TestStoreFor_Unknown(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.StoreFor(sopswrap.Format("toml"))
	require.Error(t, err)
}

func TestFormatFromPath_AutoDetect(t *testing.T) {
	t.Parallel()
	tests := map[string]sopswrap.Format{
		"secrets.yaml":   sopswrap.FormatYAML,
		"secrets.yml":    sopswrap.FormatYAML,
		"secrets.json":   sopswrap.FormatJSON,
		"secrets.env":    sopswrap.FormatDotenv,
		"secrets.ini":    sopswrap.FormatINI,
		"secrets.binary": sopswrap.FormatBinary,
		"secrets.txt":    sopswrap.FormatBinary, // fallback
	}
	for path, want := range tests {
		path, want := path, want
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			got := sopswrap.FormatFromPath(path)
			require.Equal(t, want, got)
		})
	}
}
