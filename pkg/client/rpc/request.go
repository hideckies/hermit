package rpc

import (
	"io"
	"strings"

	"github.com/hideckies/hermit/pkg/client/state"
	"github.com/hideckies/hermit/pkg/common/crypt"
	"github.com/hideckies/hermit/pkg/protobuf/commonpb"
	"github.com/hideckies/hermit/pkg/protobuf/rpcpb"
	"github.com/hideckies/hermit/pkg/server/agent"
	"github.com/hideckies/hermit/pkg/server/listener"
	"github.com/hideckies/hermit/pkg/server/operator"
	"github.com/hideckies/hermit/pkg/server/payload"
)

func RequestSayHello(clientState *state.ClientState) (string, error) {
	r, err := clientState.RPCClient.SayHello(clientState.Ctx, &commonpb.Empty{})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestGetVersion(clientState *state.ClientState) (string, error) {
	r, err := clientState.RPCClient.GetVersion(clientState.Ctx, &commonpb.Empty{})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestOperatorRegister(clientState *state.ClientState) (string, error) {
	r, err := clientState.RPCClient.OperatorRegister(clientState.Ctx, &rpcpb.Operator{
		Id:    -1, // this value is not used
		Uuid:  clientState.Conf.Uuid,
		Name:  clientState.Conf.Operator,
		Login: "",
	})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestOperatorDeleteByUuid(clientState *state.ClientState) (string, error) {
	r, err := clientState.RPCClient.OperatorDeleteByUuid(
		clientState.Ctx,
		&commonpb.Uuid{Value: clientState.Conf.Uuid},
	)
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestOperatorGetById(clientState *state.ClientState, operatorId uint) (*operator.Operator, error) {
	r, err := clientState.RPCClient.OperatorGetById(clientState.Ctx, &commonpb.Id{Value: int64(operatorId)})
	if err != nil {
		return nil, err
	}

	return operator.NewOperator(uint(r.GetId()), r.GetUuid(), r.GetName(), r.GetLogin()), nil
}

func RequestOperatorGetAll(clientState *state.ClientState) ([]*operator.Operator, error) {
	stream, err := clientState.RPCClient.OperatorGetAll(clientState.Ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}

	ops := []*operator.Operator{}

	for {
		data, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		newOp := operator.NewOperator(uint(data.GetId()), data.GetUuid(), data.GetName(), data.GetLogin())
		ops = append(ops, newOp)
	}

	return ops, nil
}

func RequestListenerStart(clientState *state.ClientState, lis *listener.Listener) (string, error) {
	r, err := clientState.RPCClient.ListenerStart(clientState.Ctx, &rpcpb.Listener{
		Protocol: lis.Protocol,
		Host:     lis.Addr,
		Port:     int32(lis.Port),
		Domains:  strings.Join(lis.Domains, ","),
	})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestListenerStartById(clientState *state.ClientState, listenerId uint) (string, error) {
	r, err := clientState.RPCClient.ListenerStartById(clientState.Ctx, &commonpb.Id{Value: int64(listenerId)})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestListenerStopById(clientState *state.ClientState, listenerId uint,
) (string, error) {
	r, err := clientState.RPCClient.ListenerStopById(clientState.Ctx, &commonpb.Id{Value: int64(listenerId)})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestListenerDeleteById(clientState *state.ClientState, listenerId uint) (string, error) {
	r, err := clientState.RPCClient.ListenerDeleteById(clientState.Ctx, &commonpb.Id{Value: int64(listenerId)})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestListenerGetById(clientState *state.ClientState, listenerId uint) (*listener.Listener, error) {
	r, err := clientState.RPCClient.ListenerGetById(clientState.Ctx, &commonpb.Id{Value: int64(listenerId)})
	if err != nil {
		return nil, err
	}
	return listener.NewListener(
		uint(r.GetId()),
		r.GetUuid(),
		r.GetName(),
		r.GetProtocol(),
		r.GetHost(),
		uint16(r.GetPort()),
		strings.Split(r.GetDomains(), ","),
		r.GetActive(),
	), nil
}

func RequestListenerPayloadsById(clientState *state.ClientState, listenerId uint,
) (string, error) {
	r, err := clientState.RPCClient.ListenerPayloadsById(clientState.Ctx, &commonpb.Id{Value: int64(listenerId)})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestListenerPayloadsDeleteById(
	clientState *state.ClientState,
	listenerId uint,
	payloadName string,
) (string, error) {
	r, err := clientState.RPCClient.ListenerPayloadsDeleteById(clientState.Ctx, &rpcpb.ListenerPayload{
		Id:          int64(listenerId),
		PayloadName: payloadName,
	})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestListenerGetAll(clientState *state.ClientState) ([]*listener.Listener, error) {
	stream, err := clientState.RPCClient.ListenerGetAll(clientState.Ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}

	listeners := []*listener.Listener{}

	for {
		lis, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		newListener := listener.NewListener(
			uint(lis.Id),
			lis.Uuid,
			lis.Name,
			lis.Protocol,
			lis.Host,
			uint16(lis.Port),
			strings.Split(lis.Domains, ","),
			lis.Active,
		)
		listeners = append(listeners, newListener)
	}

	return listeners, nil
}

func RequestPayloadImplantGenerate(clientState *state.ClientState, imp *payload.Implant) ([]byte, error) {
	r, err := clientState.RPCClient.PayloadImplantGenerate(clientState.Ctx, &rpcpb.PayloadImplant{
		Os:               imp.Os,
		Arch:             imp.Arch,
		Format:           imp.Format,
		Lprotocol:        imp.Lprotocol,
		Lhost:            imp.Lhost,
		Lport:            int32(imp.Lport),
		Type:             imp.Type,
		Sleep:            int64(imp.Sleep),
		Jitter:           int64(imp.Jitter),
		KillDate:         int64(imp.KillDate),
		IndirectSyscalls: imp.IndirectSyscalls,
	})
	if err != nil {
		return []byte{}, err
	}
	return r.GetData(), nil
}

func RequestPayloadLoaderGenerate(clientState *state.ClientState, stg *payload.Loader) ([]byte, error) {
	r, err := clientState.RPCClient.PayloadLoaderGenerate(clientState.Ctx, &rpcpb.PayloadLoader{
		Os:              stg.Os,
		Arch:            stg.Arch,
		Format:          stg.Format,
		Lhost:           stg.Lhost,
		Lport:           int32(stg.Lport),
		Type:            stg.Type,
		Technique:       stg.Technique,
		ProcessToInject: stg.ProcessToInject,
	})
	if err != nil {
		return []byte{}, err
	}
	return r.GetData(), nil
}

func RequestPayloadShellcodeGenerate(clientState *state.ClientState, shc *payload.Shellcode) ([]byte, error) {
	r, err := clientState.RPCClient.PayloadShellcodeGenerate(clientState.Ctx, &rpcpb.PayloadShellcode{
		Os:       shc.Os,
		Arch:     shc.Arch,
		Format:   shc.Format,
		Lhost:    shc.Lhost,
		Lport:    int32(shc.Lport),
		Type:     shc.Type,
		TypeArgs: shc.TypeArgs,
	})
	if err != nil {
		return []byte{}, err
	}
	return r.GetData(), nil
}

func RequestAgentDeleteById(clientState *state.ClientState, agentId uint) error {
	_, err := clientState.RPCClient.AgentDeleteById(clientState.Ctx, &commonpb.Id{Value: int64(agentId)})
	if err != nil {
		return err
	}

	return nil
}

func RequestAgentGetById(clientState *state.ClientState, agentId uint) (*agent.Agent, error) {
	r, err := clientState.RPCClient.AgentGetById(clientState.Ctx, &commonpb.Id{Value: int64(agentId)})
	if err != nil {
		return nil, err
	}

	newAES, err := crypt.NewAESFromBase64Pairs(r.GetAesKey(), r.GetAesIV())
	if err != nil {
		return nil, err
	}

	newAgent, err := agent.NewAgent(
		uint(r.GetId()),
		r.GetUuid(),
		r.GetName(),
		r.GetIp(),
		r.GetOs(),
		r.GetArch(),
		r.GetHostname(),
		r.GetListenerURL(),
		r.GetImplantType(),
		r.GetCheckInDate(),
		uint(r.GetSleep()),
		uint(r.GetJitter()),
		uint(r.GetKillDate()),
		newAES,
	)
	if err != nil {
		return nil, err
	}

	return newAgent, nil
}

func RequestAgentGetAll(clientState *state.ClientState) ([]*agent.Agent, error) {
	stream, err := clientState.RPCClient.AgentGetAll(clientState.Ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}

	agents := []*agent.Agent{}

	for {
		ag, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		newAES, err := crypt.NewAESFromBase64Pairs(ag.AesKey, ag.AesIV)
		if err != nil {
			return nil, err
		}

		newAgent, err := agent.NewAgent(
			uint(ag.Id),
			ag.Uuid,
			ag.Name,
			ag.Ip,
			ag.Os,
			ag.Arch,
			ag.Hostname,
			ag.ListenerURL,
			ag.ImplantType,
			ag.CheckInDate,
			uint(ag.Sleep),
			uint(ag.Jitter),
			uint(ag.KillDate),
			newAES,
		)
		if err != nil {
			return nil, err
		}

		agents = append(agents, newAgent)
	}

	return agents, nil
}

func RequestTaskSetByAgentName(
	clientState *state.ClientState,
	_task string,
) error {
	_, err := clientState.RPCClient.TaskSetByAgentName(
		clientState.Ctx,
		&rpcpb.Task{Task: _task, AgentName: clientState.AgentMode.Name},
	)
	if err != nil {
		return err
	}
	return nil
}

func RequestTaskClearByAgentName(clientState *state.ClientState) error {
	_, err := clientState.RPCClient.TaskClearByAgentName(
		clientState.Ctx,
		&rpcpb.Task{AgentName: clientState.AgentMode.Name},
	)
	if err != nil {
		return err
	}
	return nil
}

func RequestTaskListByAgentName(clientState *state.ClientState) (string, error) {
	r, err := clientState.RPCClient.TaskListByAgentName(
		clientState.Ctx,
		&rpcpb.Task{AgentName: clientState.AgentMode.Name},
	)
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestLootGetAll(clientState *state.ClientState) (string, error) {
	r, err := clientState.RPCClient.LootGetAll(
		clientState.Ctx,
		&rpcpb.Loot{AgentName: clientState.AgentMode.Name},
	)
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

func RequestLootClearByAgentName(clientState *state.ClientState, agentName string) (string, error) {
	r, err := clientState.RPCClient.LootClearByAgentName(clientState.Ctx, &rpcpb.Loot{AgentName: agentName})
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}
