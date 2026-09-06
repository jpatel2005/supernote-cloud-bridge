package storage

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

var ErrInvalidPath = errors.New("invalid storage path")

func NormalizePath(storagePath string) (string, error) {
	if storagePath == "" {
		return "", fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	if !strings.HasPrefix(storagePath, "/") {
		return "", fmt.Errorf("%w: path must be absolute", ErrInvalidPath)
	}
	if storagePath != path.Clean(storagePath) {
		return "", fmt.Errorf("%w: path is not normalized", ErrInvalidPath)
	}
	return storagePath, nil
}

func JoinPath(parentPath, name string) (string, error) {
	normalizedPath, err := NormalizePath(parentPath)
	if err != nil {
		return "", err
	}
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("%w: invalid path name", ErrInvalidPath)
	}
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("%w: path name must not contain '/'", ErrInvalidPath)
	}
	joinedPath := path.Join(normalizedPath, name)
	return NormalizePath(joinedPath)
}

func BaseName(storagePath string) (string, error) {
	normalizedPath, err := NormalizePath(storagePath)
	if err != nil {
		return "", err
	}
	if normalizedPath == "/" {
		return "", fmt.Errorf("%w: root path has no base name", ErrInvalidPath)
	}
	return path.Base(normalizedPath), nil
}
