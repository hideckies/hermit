package job

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/server/db"
	"github.com/hideckies/hermit/pkg/server/listener"
)

func (j *Job) WaitListenerStart(database *db.Database, lis *listener.Listener) error {
	for {
		select {
		case <-j.ChListenerReady:
			lis.Active = true

			// Add the listener to database or update
			exists, err := database.ListenerExistsByUuid(lis.Uuid)
			if err != nil {
				return err
			}
			if exists {
				err := database.ListenerUpdateActiveByUuid(lis.Uuid, true)
				if err != nil {
					return err
				}
			} else {
				err := database.ListenerAdd(lis)
				if err != nil {
					return err
				}
			}
			return nil
		case <-j.ChListenerError:
			return fmt.Errorf("error starting a listener")
		default:
		}
	}
}

func (j *Job) WaitListenerStop(database *db.Database, lis *listener.Listener) error {
	for {
		select {
		case <-j.ChListenerError:
			return fmt.Errorf("error stopping a listener")
		case <-j.ChListenerQuit:
			// Set "inactive" on the database
			err := database.ListenerUpdateActiveByUuid(lis.Uuid, false)
			if err != nil {
				return err
			}
			return nil
		default:
		}
	}
}
