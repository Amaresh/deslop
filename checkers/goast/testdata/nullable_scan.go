package testdata

import (
	"database/sql"
)

type Bike struct {
	ID      int64
	OwnerID int64
}

// listBikes: LEFT JOIN query, Scan into a grouped var block.
func listBikes(db *sql.DB) ([]Bike, error) {
	rows, err := db.Query(`
		SELECT b.id, b.owner_id
		FROM bikes b
		LEFT JOIN owners o ON o.id = b.owner_id
		WHERE o.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		id     int64
		bikeID int64
	)
	out := []Bike{}
	for rows.Next() {
		if err := rows.Scan(&id, &bikeID); err != nil {
			return nil, err
		}
		out = append(out, Bike{ID: id, OwnerID: bikeID})
	}
	return out, rows.Err()
}

// getAvatar: separately-declared plain string scanned from QueryRow.
func getAvatar(db *sql.DB, userID int64) (string, error) {
	var avatarURL string
	err := db.QueryRow(`SELECT avatar_url FROM users WHERE id = ?`, userID).Scan(&avatarURL)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return avatarURL, err
}

// getBio: nullable column correctly scanned into sql.NullString.
func getBio(db *sql.DB, userID int64) (string, error) {
	var bio sql.NullString
	err := db.QueryRow(`SELECT bio FROM profiles WHERE user_id = ?`, userID).Scan(&bio)
	if err != nil {
		return "", err
	}
	return bio.String, nil
}
