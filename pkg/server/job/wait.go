package job

import (
	"fmt"

	"github.com/hideckies/hermit/pkg/server/db"
	"github.com/hideckies/hermit/pkg/server/listener"
)

func (j *Job) WaitListenerStart(database *db.Database, lis *listener.Listener, lisJob *ListenerJob) error {
	for {
		select {
		// case <-j.ChListenerReady:
		case <-lisJob.ChReady:
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
		// case <-j.ChListenerError:
		case <-lisJob.ChError:
			return fmt.Errorf("error starting a listener")
		default:
		}
	}
}

func (j *Job) WaitListenerStop(database *db.Database, lis *listener.Listener) error {
	// Get listener job
	lisJob, err := j.GetListenerJob(lis.Uuid)
	if err != nil {
		return err
	}

	for {
		select {
		case <-lisJob.ChError:
			return fmt.Errorf("error stopping a listener")
		case <-lisJob.ChQuit:
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
