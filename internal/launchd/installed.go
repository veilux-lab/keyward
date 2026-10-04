package launchd

import (
	"encoding/xml"
	"errors"
	"io"
	"os"

	"github.com/veilux-lab/keyward/internal/vault"
	"golang.org/x/sys/unix"
)

type plistValue struct {
	XMLName xml.Name
	Text    string       `xml:",chardata"`
	Values  []plistValue `xml:",any"`
}

func plistDictionary(value plistValue) (map[string]plistValue, bool) {
	if value.XMLName.Local != "dict" || len(value.Values)%2 != 0 {
		return nil, false
	}
	dict := make(map[string]plistValue)
	for i := 0; i < len(value.Values); i += 2 {
		key := value.Values[i]
		if key.XMLName.Local != "key" {
			return nil, false
		}
		if _, exists := dict[key.Text]; exists {
			return nil, false
		}
		dict[key.Text] = value.Values[i+1]
	}
	return dict, true
}

func (m Manager) installedConfiguration(path, binary string) error {
	missing := errors.New("the signed Keyward installation is missing; run `make install` or `keyward service install` with an Apple-signed build")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return missing
	}
	if err != nil {
		return errors.New("could not safely open the installed daemon configuration")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateStartupInfo(info, false) {
		return errors.New("installed daemon configuration must be regular, owned by you, and mode 600")
	}
	content, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(content) > 65536 {
		return errors.New("could not read the installed daemon configuration")
	}
	var value plistValue
	if xml.Unmarshal(content, &value) != nil || value.XMLName.Local != "plist" || len(value.Values) != 1 {
		return errors.New("installed daemon configuration is invalid; run `keyward service install`")
	}
	dict, valid := plistDictionary(value.Values[0])
	_, program := dict["Program"]
	_, bundleProgram := dict["BundleProgram"]
	args := dict["ProgramArguments"]
	env, envValid := plistDictionary(dict["EnvironmentVariables"])
	service := m.Service
	if service == "" {
		service = vault.DefaultService
	}
	stringIs := func(v plistValue, expected string) bool { return v.XMLName.Local == "string" && v.Text == expected }
	if !valid || program || bundleProgram || !stringIs(dict["Label"], m.Label) || args.XMLName.Local != "array" || len(args.Values) != 2 ||
		!stringIs(args.Values[0], binary) || !stringIs(args.Values[1], "daemon") || !envValid ||
		!stringIs(env["KEYWARD_SOCKET"], m.socket()) || !stringIs(env["KEYWARD_SERVICE"], service) {
		return errors.New("installed daemon configuration does not match this socket and service; run `keyward service install`")
	}
	info, err = os.Lstat(binary)
	if os.IsNotExist(err) {
		return missing
	}
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("installed daemon must be a regular executable; run `make install`")
	}
	return nil
}
