package operator

type Operator struct {
	Id   uint
	Uuid string
	Name string
}

func NewOperator(id uint, uuid string, name string) *Operator {
	return &Operator{
		Id:   id,
		Uuid: uuid,
		Name: name,
	}
}
