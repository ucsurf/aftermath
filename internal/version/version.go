// Package version is the aftermath release string.
// The release workflow overrides Version with -X.
package version

// Version is the CLI version. Release builds replace it via -ldflags.
var Version = "0.1.0"
