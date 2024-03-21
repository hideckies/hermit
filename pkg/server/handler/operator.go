package handler

import (
	"github.com/hideckies/hermit/pkg/server/db"
	"github.com/hideckies/hermit/pkg/server/operator"
)

func OperatorRegister(operatorUuid string, operatorName string, database *db.Database) (*operator.Operator, error) {
	ope := operator.NewOperator(0, operatorUuid, operatorName, "")
	err := database.OperatorAdd(ope)
	if err != nil {
		return nil, err
	}
	return ope, nil
}
