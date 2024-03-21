package operator

import "github.com/hideckies/hermit/pkg/common/meta"

type Operator struct {
	Id    uint
	Uuid  string
	Name  string
	Login string // Datetime
}

func NewOperator(id uint, uuid string, name string, login string) *Operator {
	if login == "" {
		login = meta.GetCurrentDateTime()
	}

	return &Operator{
		Id:    id,
		Uuid:  uuid,
		Name:  name,
		Login: login,
	}
}
