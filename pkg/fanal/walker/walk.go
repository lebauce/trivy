package walker

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

var (
	// These variables are exported so that a tool importing Trivy as a library can override these values.
	AppDirs    = []string{".git", "proc"}
	SystemDirs = []string{"host", "proc", "sys", "dev", "run", "/var/run"}
)

const (
	defaultSizeThreshold = int64(200) << 20 // 200MB
	slowSizeThreshold    = int64(100) << 10 // 10KB
)

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error

type walker struct {
	skipFiles []string
	skipDirs  []string
	onlyDirs  []string
	slow      bool
}

func newWalker(skipFiles, skipDirs, onlyDirs []string, slow bool) walker {
	var cleanSkipFiles, cleanSkipDirs []string
	for _, skipFile := range skipFiles {
		skipFile = filepath.ToSlash(filepath.Clean(skipFile))
		skipFile = strings.TrimLeft(skipFile, "/")
		cleanSkipFiles = append(cleanSkipFiles, skipFile)
	}

	for _, skipDir := range append(skipDirs, SystemDirs...) {
		skipDir = filepath.ToSlash(filepath.Clean(skipDir))
		skipDir = strings.TrimLeft(skipDir, "/")
		cleanSkipDirs = append(cleanSkipDirs, skipDir)
	}

	var cleanOnlyDirs []string
	for _, onlyDir := range onlyDirs {
		onlyDir = filepath.ToSlash(filepath.Clean(onlyDir))
		onlyDir = strings.TrimLeft(onlyDir, "/")
		cleanOnlyDirs = append(cleanOnlyDirs, onlyDir)
	}

	return walker{
		skipFiles: cleanSkipFiles,
		skipDirs:  cleanSkipDirs,
		onlyDirs:  cleanOnlyDirs,
		slow:      slow,
	}
}

func (w *walker) shouldSkipFile(filePath string) bool {
	filePath = filepath.ToSlash(filePath)
	filePath = strings.TrimLeft(filePath, "/")

	// skip files
	return utils.StringInSlice(filePath, w.skipFiles)
}

func (w *walker) shouldSkipDir(dir string) bool {
	dir = filepath.ToSlash(dir)
	dir = strings.TrimLeft(dir, "/")

	// Skip application dirs (relative path)
	base := filepath.Base(dir)
	if utils.StringInSlice(base, AppDirs) {
		return true
	}

	// Skip system dirs and specified dirs (absolute path)
	if utils.StringInSlice(dir, w.skipDirs) {
		return true
	}

	if dir != "." && len(w.onlyDirs) > 0 {
		for _, onlyDir := range w.onlyDirs {
			if strings.HasPrefix(dir, onlyDir) || strings.HasPrefix(onlyDir, dir) {
				return false
			}
		}
		return true
	}

	return false
}
