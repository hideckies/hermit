package db

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/server/agent"
)

func (d *Database) AgentAdd(ag *agent.Agent) error {
	exists, err := d.AgentExistsByUuid(ag.Uuid)
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
	INSERT INTO agent (
		uuid, name, ip, os, arch, hostname, listener, sleep, jitter, killdate
	) VALUES (
		?, ?, ?, ?, ?, ?, ?, ?, ?, ?
	)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		ag.Uuid,
		ag.Name,
		ag.Ip,
		ag.OS,
		ag.Arch,
		ag.Hostname,
		ag.ListenerName,
		int(ag.Sleep),
		int(ag.Jitter),
		int(ag.KillDate),
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

func (d *Database) AgentExistsByUuid(uuid string) (bool, error) {
	rows, err := d.DB.Query("SELECT uuid FROM agent")
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

func (d *Database) AgentUpdate(ag *agent.Agent) error {
	exists, err := d.AgentExistsByUuid(ag.Uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("agent does not exist so cannot update")
	}

	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := d.DB.Prepare(`
	UPDATE agent
	SET name = ?, ip = ?, os = ?, arch = ?, hostname = ?, listener = ?, sleep = ?, jitter = ?, killdate = ?
	WHERE uuid = ?
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(
		ag.Name,
		ag.Ip,
		ag.OS,
		ag.Arch,
		ag.Hostname,
		ag.ListenerName,
		int(ag.Sleep),
		int(ag.Jitter),
		int(ag.KillDate),
		ag.Uuid,
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

func (d *Database) AgentDeleteById(agentId uint) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("DELETE FROM agent WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(agentId)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) AgentDeleteByUuid(agentUuid string) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("DELETE FROM agent WHERE uuid = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(agentUuid)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) AgentDeleteAll() error {
	_, err := d.DB.Exec("DELETE FROM agent")
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) AgentGetById(agentId uint) (*agent.Agent, error) {
	stmt, err := d.DB.Prepare(`
	SELECT id, uuid, name, ip, os, arch, hostname, listener, sleep, jitter, killdate
	FROM agent WHERE id = ?
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var (
		id           int
		uuid         string
		name         string
		ip           string
		os           string
		arch         string
		hostname     string
		listenerName string
		sleep        int
		jitter       int
		killDate     int
	)
	err = stmt.QueryRow(agentId).Scan(
		&id,
		&uuid,
		&name,
		&ip,
		&os,
		&arch,
		&hostname,
		&listenerName,
		&sleep,
		&jitter,
		&killDate,
	)
	if err != nil {
		return nil, err
	}
	return agent.NewAgent(
		uint(id),
		uuid,
		name,
		ip,
		os,
		arch,
		hostname,
		listenerName,
		uint(sleep),
		uint(jitter),
		uint(killDate),
	), nil
}

func (d *Database) AgentGetByUuid(agentUuid string) (*agent.Agent, error) {
	stmt, err := d.DB.Prepare(`
	SELECT id, uuid, name, ip, os, arch, hostname, listener, sleep, jitter, killdate
	FROM agent WHERE uuid = ?
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var (
		id           int
		uuid         string
		name         string
		ip           string
		os           string
		arch         string
		hostname     string
		listenerName string
		sleep        int
		jitter       int
		killDate     int
	)
	err = stmt.QueryRow(agentUuid).Scan(
		&id,
		&uuid,
		&name,
		&ip,
		&os,
		&arch,
		&hostname,
		&listenerName,
		&sleep,
		&jitter,
		&killDate,
	)
	if err != nil {
		return nil, err
	}
	return agent.NewAgent(
		uint(id),
		uuid,
		name,
		ip,
		os,
		arch,
		hostname,
		listenerName,
		uint(sleep),
		uint(jitter),
		uint(killDate),
	), nil
}

func (d *Database) AgentGetAll() ([]*agent.Agent, error) {
	rows, err := d.DB.Query(`
	SELECT id, uuid, name, ip, os, arch, hostname, listener, sleep, jitter, killdate
	FROM agent
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ags := []*agent.Agent{}

	for rows.Next() {
		var (
			id           int
			uuid         string
			name         string
			ip           string
			os           string
			arch         string
			hostname     string
			listenerName string
			sleep        int
			jitter       int
			killDate     int
		)
		err = rows.Scan(
			&id,
			&uuid,
			&name,
			&ip,
			&os,
			&arch,
			&hostname,
			&listenerName,
			&sleep,
			&jitter,
			&killDate,
		)
		if err != nil {
			return nil, err
		}

		ag := agent.NewAgent(
			uint(id),
			uuid,
			name,
			ip,
			os,
			arch,
			hostname,
			listenerName,
			uint(sleep),
			uint(jitter),
			uint(killDate),
		)
		ags = append(ags, ag)
	}
	return ags, nil
}
