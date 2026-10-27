module github.com/webong/vigilante

go 1.26.0

require (
	github.com/webong/ext/pkg/ext-go/engine v0.1.0
	github.com/webong/ext/res/system v0.2.0
)

require golang.org/x/sys v0.29.0 // indirect

replace (
	github.com/webong/ext/pkg/ext-go/engine => ../ext/pkg/ext-go/engine
	github.com/webong/ext/res/system => ../ext/res/system
)
