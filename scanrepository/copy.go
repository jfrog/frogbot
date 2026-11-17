package scanrepository

import (
	"io/fs"
	"os"
	"path/filepath"

	biutils "github.com/jfrog/build-info-go/utils"
)

// copyRepository preserves symbolic links without following them, including links
// to directories and links whose targets do not exist in the working tree.
func copyRepository(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err = os.Remove(target); err != nil && !os.IsNotExist(err) {
				return err
			}
			return os.Symlink(link, target)
		}
		return biutils.CopyFile(filepath.Dir(target), path)
	})
}
