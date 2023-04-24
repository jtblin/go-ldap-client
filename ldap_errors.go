package ldap

type LDAPError struct {
	Msg string
	Err error
}

func (le *LDAPError) Error() string {
	return le.Msg
}

func (le *LDAPError) Unwrap() error {
	return le.Err
}

func NewLDAPError(msg string, err error) *LDAPError {
	return &LDAPError{Msg: msg, Err: err}
}