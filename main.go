package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/u-root/u-root/pkg/ldd"
)

func must(err error, msg string) {
	if err != nil {
		slog.Default().Error(msg, "err", err)
		panic(err)
	}
}

func addPath(list []string, path string) ([]string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return list, err
	}
	list = append(list, abs)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return list, err
	}
	if resolved != abs {
		list = append(list, resolved)
	}
	return list, err
}

func main() {
	var rof []string
	var rwf []string
	var rod []string
	var rwd []string

	var allEnvs bool

	var connect []uint16
	var bind []uint16

	var env []string

	flag.Func("rof", "allow read-only access to a file", func(path string) error {
		var err error
		rof, err = addPath(rof, path)
		return err
	})
	flag.Func("rwf", "allow read-write access to a file", func(path string) error {
		var err error
		rwf, err = addPath(rwf, path)
		return err
	})
	flag.Func("rod", "allow read-only access to a directory", func(path string) error {
		var err error
		rod, err = addPath(rod, path)
		return err
	})
	flag.Func("rwd", "allow read-write access to a directory", func(path string) error {
		var err error
		rwd, err = addPath(rwd, path)
		return err
	})

	flag.Func("bind", "allow binding/listening on the specific TCP port", func(s string) error {
		u, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return err
		}
		bind = append(bind, uint16(u))
		return nil
	})
	flag.Func("conn", "allow connecting to the specified TCP port", func(s string) error {
		u, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return err
		}
		connect = append(connect, uint16(u))
		return nil
	})
	flag.Func("http", "allow connecting to the standard HTTP ports, 53, 80, 443", func(_ string) error {
		connect = append(connect, 80, 443, 53)
		return nil
	})
	flag.Func("env", "pass the specified env variable from to the process", func(s string) error {
		env = append(env, s)
		return nil
	})
	flag.BoolVar(&allEnvs, "all-envs", false, "pass all environment variables from the current environment to the process")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		slog.Default().Error("no command provided")
		os.Exit(1)
	}

	cmdarg := args[0]
	args = args[1:]

	// Need to include execute permissions for the path of the command specified
	cmdPath, err := exec.LookPath(cmdarg)
	must(err, "failed to find command in PATH")

	ownPath, err := os.Executable()
	must(err, "failed to determine current executable path")

	libs, err := ldd.FList(cmdPath)
	must(err, "could not determine shared libraries for command")

	rof = append(rof, cmdPath, ownPath)
	rof = append(rof, libs...)

	slog.Default().Debug("file restrictions", "ro_files", rof, "ro_dirs", rod, "rw_files", rwf, "rw_dirs", rwd)

	cfg := landlock.V8.BestEffort()

	rules := make([]landlock.Rule, 0, 4+len(connect)+len(bind))

	rules = append(rules,
		landlock.ROFiles(rof...),
		landlock.RODirs(rod...),
		landlock.RWFiles(rwf...),
		landlock.RWDirs(rwd...),
	)

	// convert port lists to rules lists
	for _, port := range connect {
		rules = append(rules, landlock.ConnectTCP(port))
	}
	for _, port := range bind {
		rules = append(rules, landlock.BindTCP(port))
	}

	must(cfg.Restrict(
		rules...,
	), "failed to set landlock restrictions")

	cmd := exec.Command(cmdarg, args...)
	if !allEnvs {
		cmd.Env = make([]string, 0, len(env))
		for _, name := range env {
			value, ok := os.LookupEnv(name)
			if ok {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", name, value))
			}
		}
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	slog.Default().Debug("executing command", "cmd", cmd.String())

	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ProcessState != nil {
			os.Exit(ee.ProcessState.ExitCode())
		}
		slog.Default().Error("failed to execute command", "err", err)
		os.Exit(1)
	}
}
