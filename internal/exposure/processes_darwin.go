package exposure

import (
	"os"

	"golang.org/x/sys/unix"
)

// Processes lists this user's running programs with their arguments. One that
// exits before its arguments are read is skipped.
func Processes() ([]Process, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Getuid())
	if err != nil {
		return nil, err
	}
	var out []Process
	for _, p := range procs {
		pid := int(p.Proc.P_pid)
		raw, err := unix.SysctlRaw("kern.procargs2", pid)
		if err != nil {
			continue
		}
		if path, args, ok := parseArgs(raw); ok {
			out = append(out, Process{PID: pid, Path: path, Args: args})
		}
	}
	return out, nil
}
