package file

import (
	"fmt"
	"os"
	"path/filepath"
)

func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "atomic-")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		if err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err = tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err = os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}

	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}
