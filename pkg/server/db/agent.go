package db

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/common/crypt"
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
		uuid,
		name,
		ip,
		os,
		arch,
		hostname,
		listenerURL,
		implantType,
		checkin,
		sleep,
		jitter,
		killdate,
		aesKey,
		aesIV,
		sessionId
	) VALUES (
		?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
		ag.ListenerURL,
		ag.ImplantType,
		ag.CheckInDate,
		int(ag.Sleep),
		int(ag.Jitter),
		int(ag.KillDate),
		ag.AES.Key.Base64,
		ag.AES.IV.Base64,
		ag.SessionId,
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
	UPDATE
		agent
	SET
		name 		= ?,
		ip 			= ?,
		os 			= ?,
		arch 		= ?,
		hostname 	= ?,
		listenerURL	= ?,
		implantType = ?,
		checkin 	= ?,
		sleep 		= ?,
		jitter 		= ?,
		killdate 	= ?,
		aesKey		= ?,
		aesIV 		= ?,
		sessionId	= ?
	WHERE
		uuid = ?
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
		ag.ListenerURL,
		ag.ImplantType,
		ag.CheckInDate,
		int(ag.Sleep),
		int(ag.Jitter),
		int(ag.KillDate),
		ag.AES.Key.Base64,
		ag.AES.IV.Base64,
		ag.SessionId,
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
	SELECT
		id,
		uuid,
		name,
		ip,
		os,
		arch,
		hostname,
		listenerURL,
		implantType,
		checkin,
		sleep,
		jitter,
		killdate,
		aesKey,
		aesIV,
		sessionId
	FROM
		agent
	WHERE
		id = ?
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var (
		id          int
		uuid        string
		name        string
		ip          string
		os          string
		arch        string
		hostname    string
		listenerURL string
		implantType string
		checkIn     string
		sleep       int
		jitter      int
		killDate    int
		aesKey      string
		aesIV       string
		sessionId   string
	)
	err = stmt.QueryRow(agentId).Scan(
		&id,
		&uuid,
		&name,
		&ip,
		&os,
		&arch,
		&hostname,
		&listenerURL,
		&implantType,
		&checkIn,
		&sleep,
		&jitter,
		&killDate,
		&aesKey,
		&aesIV,
		&sessionId,
	)
	if err != nil {
		return nil, err
	}

	newAES, err := crypt.NewAESFromBase64Pairs(aesKey, aesIV)
	if err != nil {
		return nil, err
	}

	newAgent, err := agent.NewAgent(
		uint(id),
		uuid,
		name,
		ip,
		os,
		arch,
		hostname,
		listenerURL,
		implantType,
		checkIn,
		uint(sleep),
		uint(jitter),
		uint(killDate),
		newAES,
		sessionId,
	)
	if err != nil {
		return nil, err
	}

	return newAgent, nil
}

func (d *Database) AgentGetByUuid(agentUuid string) (*agent.Agent, error) {
	stmt, err := d.DB.Prepare(`
	SELECT
		id,
		uuid,
		name,
		ip,
		os,
		arch,
		hostname,
		listenerURL,
		implantType,
		checkin,
		sleep,
		jitter,
		killdate,
		aesKey,
		aesIV,
		sessionId
	FROM
		agent
	WHERE
		uuid = ?
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var (
		id          int
		uuid        string
		name        string
		ip          string
		os          string
		arch        string
		hostname    string
		listenerURL string
		implantType string
		checkIn     string
		sleep       int
		jitter      int
		killDate    int
		aesKey      string
		aesIV       string
		sessionId   string
	)
	err = stmt.QueryRow(agentUuid).Scan(
		&id,
		&uuid,
		&name,
		&ip,
		&os,
		&arch,
		&hostname,
		&listenerURL,
		&implantType,
		&checkIn,
		&sleep,
		&jitter,
		&killDate,
		&aesKey,
		&aesIV,
		&sessionId,
	)
	if err != nil {
		return nil, err
	}

	newAES, err := crypt.NewAESFromBase64Pairs(aesKey, aesIV)
	if err != nil {
		return nil, err
	}

	newAgent, err := agent.NewAgent(
		uint(id),
		uuid,
		name,
		ip,
		os,
		arch,
		hostname,
		listenerURL,
		implantType,
		checkIn,
		uint(sleep),
		uint(jitter),
		uint(killDate),
		newAES,
		sessionId,
	)
	if err != nil {
		return nil, err
	}

	return newAgent, nil
}

func (d *Database) AgentGetAll() ([]*agent.Agent, error) {
	rows, err := d.DB.Query(`
	SELECT
		id,
		uuid,
		name,
		ip,
		os,
		arch,
		hostname,
		listenerURL,
		implantType,
		checkin,
		sleep,
		jitter,
		killdate,
		aesKey,
		aesIV,
		sessionId
	FROM
		agent
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ags := []*agent.Agent{}

	for rows.Next() {
		var (
			id          int
			uuid        string
			name        string
			ip          string
			os          string
			arch        string
			hostname    string
			listenerURL string
			implantType string
			checkIn     string
			sleep       int
			jitter      int
			killDate    int
			aesKey      string
			aesIV       string
			sessionId   string
		)
		err = rows.Scan(
			&id,
			&uuid,
			&name,
			&ip,
			&os,
			&arch,
			&hostname,
			&listenerURL,
			&implantType,
			&checkIn,
			&sleep,
			&jitter,
			&killDate,
			&aesKey,
			&aesIV,
			&sessionId,
		)
		if err != nil {
			return nil, err
		}

		newAES, err := crypt.NewAESFromBase64Pairs(aesKey, aesIV)
		if err != nil {
			return nil, err
		}

		ag, err := agent.NewAgent(
			uint(id),
			uuid,
			name,
			ip,
			os,
			arch,
			hostname,
			listenerURL,
			implantType,
			checkIn,
			uint(sleep),
			uint(jitter),
			uint(killDate),
			newAES,
			sessionId,
		)
		if err != nil {
			return nil, err
		}

		ags = append(ags, ag)
	}
	return ags, nil
}
