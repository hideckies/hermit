package rpc

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/protobuf/commonpb"
	"github.com/hideckies/hermit/pkg/protobuf/rpcpb"
	"github.com/hideckies/hermit/pkg/server/handler"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/loot"
	"github.com/hideckies/hermit/pkg/server/payload"
	"github.com/hideckies/hermit/pkg/server/state"
)

type HermitRPCServer struct {
	rpcpb.UnimplementedHermitRPCServer
	serverState *state.ServerState
}

func (s *HermitRPCServer) SayHello(ctx context.Context, empty *commonpb.Empty) (*commonpb.Message, error) {
	return &commonpb.Message{Text: "Hello from Hermit"}, nil
}

func (s *HermitRPCServer) GetVersion(ctx context.Context, empty *commonpb.Empty) (*commonpb.Message, error) {
	return &commonpb.Message{Text: meta.GetVersion()}, nil
}

func (s *HermitRPCServer) OperatorRegister(
	ctx context.Context,
	ope *rpcpb.Operator,
) (*commonpb.Message, error) {
	_, err := handler.OperatorRegister(ope.Uuid, ope.Name, s.serverState.DB)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "You've been registered on the server successfully."}, nil
}

func (s *HermitRPCServer) OperatorDeleteByUuid(
	ctx context.Context,
	operatorUuid *commonpb.Uuid,
) (*commonpb.Message, error) {
	err := s.serverState.DB.OperatorDeleteByUuid(operatorUuid.Value)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "The operator deleted successfully."}, nil
}

func (s *HermitRPCServer) OperatorGetById(
	ctx context.Context,
	operatorId *commonpb.Id,
) (*rpcpb.Operator, error) {
	op, err := s.serverState.DB.OperatorGetById(uint(operatorId.Value))
	if err != nil {
		return nil, err
	}
	return &rpcpb.Operator{Id: int64(op.Id), Uuid: op.Uuid, Name: op.Name}, nil
}

func (s *HermitRPCServer) OperatorGetAll(
	empty *commonpb.Empty,
	stream rpcpb.HermitRPC_OperatorGetAllServer,
) error {
	ops, err := s.serverState.DB.OperatorGetAll()
	if err != nil {
		return err
	}

	for _, op := range ops {
		o := &rpcpb.Operator{
			Id:    int64(op.Id),
			Uuid:  op.Uuid,
			Name:  op.Name,
			Login: op.Login,
		}
		if err := stream.Send(o); err != nil {
			return err
		}
	}

	return nil
}

func (s *HermitRPCServer) ListenerStart(
	ctx context.Context,
	lis *rpcpb.Listener,
) (*commonpb.Message, error) {
	newLis := listener.NewListener(
		uint(lis.Id),
		lis.Uuid,
		lis.Name,
		lis.Protocol,
		lis.Host,
		uint16(lis.Port),
		strings.Split(lis.Domains, ","),
		lis.Active,
	)

	// Add new listener job
	lisJob := s.serverState.Job.NewListenerJob(lis.Uuid)

	go handler.ListenerStart(newLis, lisJob, s.serverState)
	err := s.serverState.Job.WaitListenerStart(s.serverState.DB, newLis, lisJob)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "Listener started."}, nil
}

func (s *HermitRPCServer) ListenerStartById(
	ctx context.Context,
	listenerId *commonpb.Id,
) (*commonpb.Message, error) {
	lis, err := s.serverState.DB.ListenerGetById(uint(listenerId.Value))
	if err != nil {
		return nil, err
	}
	if lis.Active {
		return nil, fmt.Errorf("the listener is already running")
	}

	// Get listener job
	lisJob, err := s.serverState.Job.GetListenerJob(lis.Uuid)
	if err != nil {
		return nil, err
	}

	go handler.ListenerStart(lis, lisJob, s.serverState)
	err = s.serverState.Job.WaitListenerStart(s.serverState.DB, lis, lisJob)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "Listener started."}, nil
}

func (s *HermitRPCServer) ListenerStopById(
	ctx context.Context,
	listenerId *commonpb.Id,
) (*commonpb.Message, error) {
	lis, err := s.serverState.DB.ListenerGetById(uint(listenerId.Value))
	if err != nil {
		return nil, err
	}
	if !lis.Active {
		return nil, fmt.Errorf("listener already stopped")
	}

	// Get listener job and send quit request to channel
	lisJob, err := s.serverState.Job.GetListenerJob(lis.Uuid)
	if err != nil {
		return nil, err
	}

	// s.serverState.Job.ChReqListenerQuit <- lis.Uuid
	lisJob.ChReqQuit <- lis.Uuid
	err = s.serverState.Job.WaitListenerStop(s.serverState.DB, lis)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "Listener stoped."}, nil
}

func (s *HermitRPCServer) ListenerDeleteById(
	ctx context.Context,
	listenerId *commonpb.Id,
) (*commonpb.Message, error) {
	lis, err := s.serverState.DB.ListenerGetById(uint(listenerId.Value))
	if err != nil {
		return nil, err
	}
	if lis.Active {
		return nil, fmt.Errorf("the listener is running. Stop it before deleting")
	}

	err = s.serverState.DB.ListenerDeleteById(uint(listenerId.Value))
	if err != nil {
		return nil, err
	}

	// Delete folder
	listenerDir, err := metafs.GetListenerDir(lis.Name, false)
	if err != nil {
		return nil, err
	}
	err = os.RemoveAll(listenerDir)
	if err != nil {
		return nil, err
	}

	return &commonpb.Message{Text: "Listener deleted."}, nil
}

func (s *HermitRPCServer) ListenerPayloadsById(
	ctx context.Context,
	listenerId *commonpb.Id,
) (*commonpb.Message, error) {
	lis, err := s.serverState.DB.ListenerGetById(uint(listenerId.Value))
	if err != nil {
		return nil, err
	}

	// List payloads on the listener
	payloads, err := metafs.GetListenerPayloadPaths(lis.Name, false, true)
	if err != nil {
		return nil, err
	}
	if len(payloads) == 0 {
		return nil, fmt.Errorf("payloads not found on the listener")
	}

	return &commonpb.Message{Text: strings.Join(payloads, "\n")}, nil
}

func (s *HermitRPCServer) ListenerPayloadsDeleteById(
	ctx context.Context,
	listenerPayload *rpcpb.ListenerPayload,
) (*commonpb.Message, error) {
	listenerId := listenerPayload.Id
	payloadName := listenerPayload.PayloadName

	lis, err := s.serverState.DB.ListenerGetById(uint(listenerId))
	if err != nil {
		return nil, err
	}

	payloadsDir, err := metafs.GetListenerPayloadsDir(lis.Name, false)
	if err != nil {
		return nil, err
	}
	err = os.RemoveAll(fmt.Sprintf("%s/%s", payloadsDir, payloadName))
	if err != nil {
		return nil, err
	}

	return &commonpb.Message{Text: "Payload deleted."}, nil
}

func (s *HermitRPCServer) ListenerGetById(
	ctx context.Context,
	listenerId *commonpb.Id,
) (*rpcpb.Listener, error) {
	lis, err := s.serverState.DB.ListenerGetById(uint(listenerId.Value))
	if err != nil {
		return nil, err
	}
	return &rpcpb.Listener{
		Id:       int64(lis.Id),
		Uuid:     lis.Uuid,
		Name:     lis.Name,
		Protocol: lis.Protocol,
		Host:     lis.Addr,
		Domains:  strings.Join(lis.Domains, ","),
		Port:     int32(lis.Port),
		Active:   lis.Active,
	}, nil
}

func (s *HermitRPCServer) ListenerGetAll(
	empty *commonpb.Empty,
	stream rpcpb.HermitRPC_ListenerGetAllServer,
) error {
	liss, err := s.serverState.DB.ListenerGetAll()
	if err != nil {
		return err
	}

	for _, lis := range liss {
		l := &rpcpb.Listener{
			Id:       int64(lis.Id),
			Uuid:     lis.Uuid,
			Name:     lis.Name,
			Protocol: lis.Protocol,
			Host:     lis.Addr,
			Domains:  strings.Join(lis.Domains, ","),
			Port:     int32(lis.Port),
			Active:   lis.Active,
		}
		if err := stream.Send(l); err != nil {
			return err
		}
	}

	return nil
}

func (s *HermitRPCServer) PayloadImplantGenerate(
	ctx context.Context,
	imp *rpcpb.PayloadImplant,
) (*commonpb.Binary, error) {
	newImp := payload.NewImplant(
		uint(imp.Id),
		imp.Uuid,
		imp.Name,
		imp.Os,
		imp.Arch,
		imp.Format,
		imp.Lprotocol,
		imp.Lhost,
		uint16(imp.Lport),
		imp.Type,
		uint(imp.Sleep),
		uint(imp.Jitter),
		uint(imp.KillDate),
	)
	data, _, err := newImp.Generate(s.serverState)
	if err != nil {
		return nil, err
	}
	return &commonpb.Binary{Data: data}, nil
}

func (s *HermitRPCServer) PayloadStagerGenerate(
	ctx context.Context,
	stg *rpcpb.PayloadStager,
) (*commonpb.Binary, error) {
	newStg := payload.NewStager(
		uint(stg.Id),
		stg.Uuid,
		stg.Name,
		stg.Os,
		stg.Arch,
		stg.Format,
		stg.Lprotocol,
		stg.Lhost,
		uint16(stg.Lport),
		stg.Type,
		stg.Technique,
		stg.ProcessToInject,
	)
	data, _, err := newStg.Generate(s.serverState)
	if err != nil {
		return nil, err
	}
	return &commonpb.Binary{Data: data}, nil
}

func (s *HermitRPCServer) PayloadShellcodeGenerate(
	ctx context.Context,
	shc *rpcpb.PayloadShellcode,
) (*commonpb.Binary, error) {
	newShc := payload.NewShellcode(
		uint(shc.Id),
		shc.Uuid,
		shc.Name,
		shc.Os,
		shc.Arch,
		shc.Format,
		shc.Lprotocol,
		shc.Lhost,
		uint16(shc.Lport),
		shc.Type,
		shc.TypeArgs,
	)
	data, _, err := newShc.Generate(s.serverState)
	if err != nil {
		return nil, err
	}
	return &commonpb.Binary{Data: data}, nil
}

func (s *HermitRPCServer) AgentDeleteById(
	ctx context.Context,
	agentId *commonpb.Id,
) (*commonpb.Message, error) {
	ag, err := s.serverState.DB.AgentGetById(uint(agentId.Value))
	if err != nil {
		return nil, err
	}

	// Delete the agent from database
	err = s.serverState.DB.AgentDeleteById(uint(agentId.Value))
	if err != nil {
		return nil, err
	}

	// Delete the related folder
	lootAgentDir, err := metafs.GetAgentLootDir(ag.Name, false)
	if err != nil {
		return nil, err
	}
	err = os.RemoveAll(lootAgentDir)
	if err != nil {
		return nil, err
	}

	return &commonpb.Message{Text: "Agent deleted."}, nil
}

func (s *HermitRPCServer) AgentGetById(
	ctx context.Context,
	agentId *commonpb.Id,
) (*rpcpb.Agent, error) {
	ag, err := s.serverState.DB.AgentGetById(uint(agentId.Value))
	if err != nil {
		return nil, err
	}
	return &rpcpb.Agent{
		Id:          int64(ag.Id),
		Uuid:        ag.Uuid,
		Name:        ag.Name,
		Ip:          ag.Ip,
		Os:          ag.OS,
		Arch:        ag.Arch,
		Hostname:    ag.Hostname,
		ListenerURL: ag.ListenerURL,
		ImplantType: ag.ImplantType,
		CheckInDate: ag.CheckInDate,
		Sleep:       int64(ag.Sleep),
		Jitter:      int64(ag.Jitter),
		KillDate:    int64(ag.KillDate),
	}, nil
}

func (s *HermitRPCServer) AgentGetAll(
	empty *commonpb.Empty,
	stream rpcpb.HermitRPC_AgentGetAllServer,
) error {
	ags, err := s.serverState.DB.AgentGetAll()
	if err != nil {
		return err
	}

	for _, ag := range ags {
		a := &rpcpb.Agent{
			Id:          int64(ag.Id),
			Uuid:        ag.Uuid,
			Name:        ag.Name,
			Ip:          ag.Ip,
			Os:          ag.OS,
			Arch:        ag.Arch,
			Hostname:    ag.Hostname,
			ListenerURL: ag.ListenerURL,
			ImplantType: ag.ImplantType,
			CheckInDate: ag.CheckInDate,
			Sleep:       int64(ag.Sleep),
			Jitter:      int64(ag.Jitter),
			KillDate:    int64(ag.KillDate),
		}
		if err := stream.Send(a); err != nil {
			return err
		}
	}
	return nil
}

func (s *HermitRPCServer) TaskSetByAgentName(
	ctx context.Context,
	_task *rpcpb.Task,
) (*commonpb.Message, error) {
	// Add the task to the '.tasks' file
	err := metafs.WriteAgentTask(_task.GetAgentName(), _task.GetTask(), false)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "Task set successfully."}, nil
}

func (s *HermitRPCServer) TaskClearByAgentName(
	ctx context.Context,
	_task *rpcpb.Task,
) (*commonpb.Message, error) {
	err := metafs.DeleteAllAgentTasks(_task.GetAgentName(), false)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "All tasks deleted successfully."}, nil
}

func (s *HermitRPCServer) TaskListByAgentName(
	ctx context.Context,
	_task *rpcpb.Task,
) (*commonpb.Message, error) {
	tasks, err := metafs.ReadAgentTasks(_task.GetAgentName(), false)
	if err != nil {
		return nil, err
	}

	if len(tasks) == 0 {
		return nil, fmt.Errorf("task not set")
	}
	return &commonpb.Message{Text: strings.Join(tasks, "\n")}, nil
}

func (s *HermitRPCServer) LootGetAll(
	ctx context.Context,
	_loot *rpcpb.Loot,
) (*commonpb.Message, error) {
	allLoot, err := loot.GetAllLoot(_loot.GetAgentName())
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: allLoot}, nil
}

func (s *HermitRPCServer) LootClearByAgentName(
	ctx context.Context,
	_loot *rpcpb.Loot,
) (*commonpb.Message, error) {
	err := metafs.DeleteAllAgentLoot(_loot.GetAgentName(), false)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "All loot deleted successfully."}, nil
}
