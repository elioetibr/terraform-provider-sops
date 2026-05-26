package resources

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/require"
)

func TestAppendDiagsHasErr_NoErrors(t *testing.T) {
	t.Parallel()
	var out fwDiags
	in := diag.Diagnostics{}
	in.AddWarning("warn", "just a warning")
	require.False(t, appendDiagsHasErr(&out, in))
	require.Equal(t, 1, len(out))
}

func TestAppendDiagsHasErr_WithError(t *testing.T) {
	t.Parallel()
	var out fwDiags
	in := diag.Diagnostics{}
	in.AddError("boom", "explained")
	require.True(t, appendDiagsHasErr(&out, in))
	require.True(t, out.HasError())
}
