package billing

import "fmt"

func (s *Store) Get(id string) error {
	_, err := s.db.Query(fmt.Sprintf("SELECT id FROM invoices WHERE status = '%s'", id))
	return err
}
