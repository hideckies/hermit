package db

import (
	"github.com/hideckies/hermit/pkg/server/operator"
)

func (d *Database) OperatorAdd(ope *operator.Operator) error {
	exists, err := d.OperatorExistsByUuid(ope.Uuid)
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

	stmt, err := tx.Prepare("INSERT INTO operator (uuid, name, login) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(ope.Uuid, ope.Name, ope.Login)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) OperatorExistsByUuid(uuid string) (bool, error) {
	rows, err := d.DB.Query("SELECT uuid FROM operator")
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

func (d *Database) OperatorDeleteById(operatorId uint) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("DELETE FROM operator WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(operatorId)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) OperatorDeleteByUuid(operatorUuid string) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("DELETE FROM operator WHERE uuid = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(operatorUuid)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) OperatorDeleteAll() error {
	_, err := d.DB.Exec("DELETE FROM operator")
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) OperatorGetById(operatorId uint) (*operator.Operator, error) {
	stmt, err := d.DB.Prepare("SELECT id, uuid, name, login FROM operator WHERE id = ?")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var (
		id    int
		uuid  string
		name  string
		login string
	)
	err = stmt.QueryRow(operatorId).Scan(&id, &uuid, &name, &login)
	if err != nil {
		return nil, err
	}
	return operator.NewOperator(uint(id), uuid, name, login), nil
}

func (d *Database) OperatorGetByUuid(operatorUuid string) (*operator.Operator, error) {
	stmt, err := d.DB.Prepare("SELECT id, uuid, name, login FROM operator WHERE uuid = ?")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var (
		id    int
		uuid  string
		name  string
		login string
	)
	err = stmt.QueryRow(operatorUuid).Scan(&id, &uuid, &name, &login)
	if err != nil {
		return nil, err
	}
	return operator.NewOperator(uint(id), uuid, name, login), nil
}

func (d *Database) OperatorGetAll() ([]*operator.Operator, error) {
	rows, err := d.DB.Query("SELECT id, uuid, name, login FROM operator")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ops := []*operator.Operator{}

	for rows.Next() {
		var (
			id    int
			uuid  string
			name  string
			login string
		)
		err = rows.Scan(&id, &uuid, &name, &login)
		if err != nil {
			return nil, err
		}

		op := operator.NewOperator(uint(id), uuid, name, login)
		ops = append(ops, op)
	}
	return ops, nil
}
