package packaging

import "embed"

//go:embed *.service
var Units embed.FS
