package mrpc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPCSign(t *testing.T) {
	assert := assert.New(t)
	assert.NotNil(assert)
	require := require.New(t)
	require.NotNil(require)

	apiKey := "testkey"
	data := map[string]interface{}{
		"foo": "bar",
	}
	signedData := RPCSign(data, apiKey)

	body, err := CheckRPCSign(signedData, apiKey)
	require.Nil(err)
	var checkData map[string]interface{}
	err = json.Unmarshal(body, &checkData)
	require.Nil(err)
	assert.Equal(data, checkData)
}
