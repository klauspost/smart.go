package test

import (
	"github.com/anatol/smart.go"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestOpen(t *testing.T) {
	path := "/dev/nvme0n1"

	dev, err := smart.Open(path)
	require.NoError(t, err)
	defer dev.Close()

	require.IsType(t, (*smart.NVMeDevice)(nil), dev)
}
