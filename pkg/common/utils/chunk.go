package utils

const MAX_TRANSFER_FILE_SIZE = 0x1e00000

func ChunkData(data []byte) (chunked [][]byte) {
	chunkSize := MAX_TRANSFER_FILE_SIZE

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunked = append(chunked, data[i:end])
	}

	return chunked
}
