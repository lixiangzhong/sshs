package file

var _ error = NotDirError{}

type NotDirError struct {
	name string
}

func (e NotDirError) Error() string {
	return e.name + " not a directory"
}
