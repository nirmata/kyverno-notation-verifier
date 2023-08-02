package setup

import (
	"log"
	"os"

	"github.com/nirmata/kyverno-notation-verifier/setup/internal"
	"github.com/notaryproject/notation-go/dir"
	"go.uber.org/zap"
)

// SetupLocal takes NOTATION_DIR and PLUGINS_DIR from env and sets up local system notation configuration
func SetupLocal(logger *zap.SugaredLogger) {
	if err := internal.InstallPlugins(); err != nil {
		log.Fatalf("failed to install plugins: %v", err)
	}

	installDir := os.Getenv("NOTATION_DIR")
	dir.UserConfigDir = installDir
	dir.UserLibexecDir = installDir
	logger.Infow("configuring notation", "dir.UserConfigDir", dir.UserConfigDir, "dir.UserLibexecDir", dir.UserLibexecDir)
}
