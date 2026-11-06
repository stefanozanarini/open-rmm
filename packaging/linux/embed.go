// Package linux holds the systemd units of the Linux agent, embedded in the
// console to build the self-extracting Linux installer.
package linux

import "embed"

// Units are the systemd unit files, by file name.
//
//go:embed *.service *.timer
var Units embed.FS
