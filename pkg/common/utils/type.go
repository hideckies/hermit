package utils

func ConvertStringsToInterfaces(input []string) []interface{} {
	output := make([]interface{}, len(input))
	for i := range input {
		output[i] = input[i]
	}
	return output
}
