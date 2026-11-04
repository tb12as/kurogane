// Package deploy embeds systemd units and packaging assets.
package deploy

import _ "embed"

//go:embed kurogane.service
var AgentUnit []byte
