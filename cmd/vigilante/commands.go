package main

// normalizeCommand preserves the flag CLI while offering placement commands.
func normalizeCommand(args []string) []string {
	if len(args) == 0 {
		return args
	}
	if args[0] == "run" {
		args = args[1:]
		if len(args) == 0 {
			return []string{"-help"}
		}
	}
	switch args[0] {
	case "passive", "inline", "reverse", "middle", "demo", "eval":
		return append([]string{"-mode", args[0]}, args[1:]...)
	}
	return args
}
