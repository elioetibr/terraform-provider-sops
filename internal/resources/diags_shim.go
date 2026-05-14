package resources

import "github.com/hashicorp/terraform-plugin-framework/diag"

// fwDiags is a type alias for the framework diagnostics slice.
type fwDiags = diag.Diagnostics

// appendDiagsHasErr appends in to *out and reports whether in contained an error.
func appendDiagsHasErr(out *fwDiags, in fwDiags) bool {
	out.Append(in...)
	return in.HasError()
}
