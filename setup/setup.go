package setup

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/notaryproject/notation-go/dir"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// SetupLocal takes NOTATION_DIR and PLUGINS_DIR from env and sets up local system notation configuration
func SetupLocal(logger *zap.SugaredLogger) {
	if err := installPlugins(); err != nil {
		log.Fatalf("failed to install plugins: %v", err)
	}

	installDir := os.Getenv("NOTATION_DIR")
	dir.UserConfigDir = installDir
	dir.UserLibexecDir = installDir
	logger.Infow("configuring notation", "dir.UserConfigDir", dir.UserConfigDir, "dir.UserLibexecDir", dir.UserLibexecDir)
}

func installPlugins() error {
	sourceDir := os.Getenv("PLUGINS_DIR")
	if sourceDir == "" {
		return errors.New("missing PLUGINS_DIR")
	}

	notationDir := os.Getenv("NOTATION_DIR")
	if notationDir == "" {
		return errors.New("missing NOTATION_DIR")
	}

	destinationDir := filepath.Join(notationDir, "plugins")
	if err := os.MkdirAll(destinationDir, 0755); err != nil {
		if !os.IsExist(err) {
			return err
		}
	}

	if err := copy(sourceDir, destinationDir); err != nil {
		if !os.IsExist(err) {
			return errors.Wrapf(err, "failed to copy %s to %s", sourceDir, destinationDir)
		}
	}

	return nil
}

func copy(source, destination string) error {
	var err error = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		var relPath string = strings.Replace(path, source, "", 1)
		if relPath == "" {
			return nil
		}
		if info.IsDir() {
			return os.Mkdir(filepath.Join(destination, relPath), 0755)
		} else {
			var data, err1 = os.ReadFile(filepath.Join(source, relPath))
			if err1 != nil {
				return err1
			}
			return os.WriteFile(filepath.Join(destination, relPath), data, 0777)
		}
	})

	return err
}
