package storage

type StorageBackend interface {
    Filesizes(string) (uint64, uint64, error)
    Delete(paths []string) error
}
