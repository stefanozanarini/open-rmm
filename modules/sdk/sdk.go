// Package sdk embeds the module SDKs, so that openrmm-admin can add them to
// modules when signing without needing the repository on disk.
package sdk

import "embed"

// FS holds powershell/OpenRmm.psm1 and sh/openrmm.sh.
//
//go:embed powershell/OpenRmm.psm1 sh/openrmm.sh
var FS embed.FS
