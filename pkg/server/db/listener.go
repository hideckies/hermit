package db

import (
	"strings"

	"github.com/hideckies/hermit/pkg/server/listener"
)

const (
	LISTENER_ACTIVE_TEXT   = "running"
	LISTENER_INACTIVE_TEXT = "inactive"
)

func (d *Database) ListenerAdd(lis *listener.Listener) error {
	exists, err := d.ListenerExistsByUuid(lis.Uuid)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
	INSERT INTO listener (
		uuid, name, protocol, host, port, domains, active
	) VALUES (
		?, ?, ?, ?, ?, ?, ?
	)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	activeTxt := LISTENER_ACTIVE_TEXT
	if !lis.Active {
		activeTxt = LISTENER_INACTIVE_TEXT
	}

	_, err = stmt.Exec(
		lis.Uuid,
		lis.Name,
		lis.Protocol,
		lis.Addr,
		int(lis.Port),
		strings.Join(lis.Domains, ","),
		activeTxt,
	)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) ListenerExistsByUuid(uuid string) (bool, error) {
	rows, err := d.DB.Query("SELECT uuid FROM listener")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var rowUuid string
		rows.Scan(&rowUuid)

		if rowUuid == uuid {
			return true, nil
		}
	}

	return false, nil
}

// Method not allowed to use type parameters so the 'value' parameter needs to be set as string.
func (d *Database) ListenerUpdateActiveByUuid(uuid string, active bool) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("UPDATE listener SET active = ? WHERE uuid = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	activeTxt := LISTENER_ACTIVE_TEXT
	if !active {
		activeTxt = LISTENER_INACTIVE_TEXT
	}
	_, err = stmt.Exec(activeTxt, uuid)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) ListenerUpdateActiveAll(active bool) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("UPDATE listener SET active = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	activeTxt := LISTENER_ACTIVE_TEXT
	if !active {
		activeTxt = LISTENER_INACTIVE_TEXT
	}
	_, err = stmt.Exec(activeTxt)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) ListenerDeleteById(listenerId uint) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return nil
	}

	stmt, err := tx.Prepare("DELETE FROM listener WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(listenerId)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) ListenerDeleteByUuid(listenerUuid string) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return nil
	}

	stmt, err := tx.Prepare("DELETE FROM listener WHERE uuid = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(listenerUuid)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) ListenerDeleteAll() error {
	_, err := d.DB.Exec("DELETE FROM listener")
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) ListenerGetById(listenerId uint) (*listener.Listener, error) {
	stmt, err := d.DB.Prepare(`
	SELECT id, uuid, name, protocol, host, port, domains, active
	FROM listener
	WHERE id = ?
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var (
		id         int
		uuid       string
		name       string
		protocol   string
		host       string
		port       int
		domainsTxt string
		activeTxt  string
	)
	err = stmt.QueryRow(listenerId).Scan(
		&id,
		&uuid,
		&name,
		&protocol,
		&host,
		&port,
		&domainsTxt,
		&activeTxt,
	)
	if err != nil {
		return nil, err
	}
	active := true
	if activeTxt == LISTENER_INACTIVE_TEXT {
		active = false
	}
	return listener.NewListener(
		uint(id),
		uuid,
		name,
		protocol,
		host,
		uint16(port),
		strings.Split(domainsTxt, ","),
		active,
	), nil
}

func (d *Database) ListenerGetByUuid(listenerUuid string) (*listener.Listener, error) {
	stmt, err := d.DB.Prepare(`
	SELECT id, uuid, name, protocol, host, port, domains, active
	FROM listener
	WHERE uuid = ?
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var (
		id         int
		uuid       string
		name       string
		protocol   string
		host       string
		port       int
		domainsTxt string
		activeTxt  string
	)
	err = stmt.QueryRow(listenerUuid).Scan(
		&id,
		&uuid,
		&name,
		&protocol,
		&host,
		&port,
		&domainsTxt,
		&activeTxt,
	)
	if err != nil {
		return nil, err
	}
	active := true
	if activeTxt == LISTENER_INACTIVE_TEXT {
		active = false
	}
	return listener.NewListener(
		uint(id),
		uuid,
		name,
		protocol,
		host,
		uint16(port),
		strings.Split(domainsTxt, ","),
		active,
	), nil
}

func (d *Database) ListenerGetAll() ([]*listener.Listener, error) {
	rows, err := d.DB.Query(`
	SELECT id, uuid, name, protocol, host, port, domains, active FROM listener
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	liss := []*listener.Listener{}

	for rows.Next() {
		var (
			id         int
			uuid       string
			name       string
			protocol   string
			host       string
			port       int
			domainsTxt string
			activeTxt  string
		)
		err = rows.Scan(
			&id,
			&uuid,
			&name,
			&protocol,
			&host,
			&port,
			&domainsTxt,
			&activeTxt,
		)
		if err != nil {
			return nil, err
		}

		active := true
		if activeTxt == LISTENER_INACTIVE_TEXT {
			active = false
		}
		lis := listener.NewListener(
			uint(id),
			uuid,
			name,
			protocol,
			host,
			uint16(port),
			strings.Split(domainsTxt, ","),
			active,
		)
		liss = append(liss, lis)
	}
	return liss, nil
}
