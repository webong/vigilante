package obs

// NewExtensionBridge composes authenticated extension routes with the existing
// obs bridge. Unknown routes retain the original behavior.
func NewExtensionBridge(ext Extension, next *Bridge) *Bridge {
	return &Bridge{extension: ext, next: next}
}
