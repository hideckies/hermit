package rpc

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hideckies/hermit/pkg/common/handler"
	"github.com/hideckies/hermit/pkg/common/meta"
	metafs "github.com/hideckies/hermit/pkg/common/meta/fs"
	"github.com/hideckies/hermit/pkg/protobuf/commonpb"
	"github.com/hideckies/hermit/pkg/protobuf/rpcpb"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/loot"
	"github.com/hideckies/hermit/pkg/server/operator"
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
	newOp := operator.NewOperator(0, ope.Uuid, ope.Name, "")
	err := s.serverState.DB.OperatorAdd(newOp)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "You've been registered on the server successfully."}, nil
}

func (s *HermitRPCServer) OperatorDeleteByUuid(
	ctx context.Context,
	operatorUUID *commonpb.Uuid,
) (*commonpb.Message, error) {
	err := s.serverState.DB.OperatorDeleteByUuid(operatorUUID.Value)
	if err != nil {
		return nil, err
	}
	return &commonpb.Message{Text: "The operator deleted successfully."}, nil
}

func (s *HermitRPCServer) OperatorGetById(
	ctx context.Context,
	operatorID *commonpb.Id,
) (*rpcpb.Operator, error) {
	op, err := s.serverState.DB.OperatorGetById(uint(operatorID.Value))
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
		imp.IndirectSyscalls,
		imp.AntiDebug,
	)
	data, _, err := newImp.Generate(s.serverState)
	if err != nil {
		return nil, err
	}
	return &commonpb.Binary{Data: data}, nil
}

func (s *HermitRPCServer) PayloadLoaderGenerate(
	ctx context.Context,
	ldr *rpcpb.PayloadLoader,
) (*commonpb.Binary, error) {
	newLdr := payload.NewLoader(
		uint(ldr.Id),
		ldr.Uuid,
		ldr.Name,
		ldr.Os,
		ldr.Arch,
		ldr.Format,
		ldr.Lprotocol,
		ldr.Lhost,
		uint16(ldr.Lport),
		ldr.Type,
		ldr.PayloadToLoad,
		ldr.Technique,
		ldr.ProcessToInject,
		ldr.IndirectSyscalls,
		ldr.AntiDebug,
	)
	data, _, err := newLdr.Generate(s.serverState)
	if err != nil {
		return nil, err
	}
	return &commonpb.Binary{Data: data}, nil
}

func (s *HermitRPCServer) PayloadModuleGenerate(
	ctx context.Context,
	mod *rpcpb.PayloadModule,
) (*commonpb.Binary, error) {
	newMod := payload.NewModule(
		uint(mod.Id),
		mod.Uuid,
		mod.Name,
		mod.Os,
		mod.Arch,
		mod.Format,
		mod.Lprotocol,
		mod.Lhost,
		uint16(mod.Lport),
		mod.Type,
	)
	data, _, err := newMod.Generate(s.serverState)
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
		AesKey:      ag.AES.Key.Base64,
		AesIV:       ag.AES.IV.Base64,
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
			AesKey:      ag.AES.Key.Base64,
			AesIV:       ag.AES.IV.Base64,
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
	allLoot, err := loot.GetAllLoot(_loot.GetAgentName(), _loot.GetFilter())
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
