package mrpc

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	// CodeRPCSuccess rpc call success code
	CodeRPCSuccess = 0
)

// errors
var (
	ErrTimeMismatch     = errors.New("time mismatch")
	ErrUnexceptedFormat = errors.New("unexpected format")
	ErrSignature        = errors.New("signature error")
)

// RPCSignV1 generate signed data for missevan rpc call (deprecated)
func RPCSignV1(data interface{}, apiKey string) []byte {
	t := time.Now().Unix()
	d, _ := json.Marshal(data)

	b64Str := base64.StdEncoding.EncodeToString(d)

	mac := hmac.New(sha1.New, []byte(apiKey))
	_, _ = mac.Write([]byte(fmt.Sprintf("%s %d", b64Str, t)))
	sign := mac.Sum(nil)
	hexSign := hex.EncodeToString(sign)

	return []byte(fmt.Sprintf("%s %s %d", b64Str, hexSign, t))
}

// RPCSign generate signed data for missevan rpc call
func RPCSign(data interface{}, apiKey string) []byte {
	t := time.Now().Unix()
	d, _ := json.Marshal(data)

	b64Str := base64.StdEncoding.EncodeToString(d)

	mac := hmac.New(sha256.New, []byte(apiKey))
	_, _ = mac.Write([]byte(fmt.Sprintf("%s %d", b64Str, t)))
	sign := mac.Sum(nil)
	hexSign := hex.EncodeToString(sign)

	return []byte(fmt.Sprintf("%s %s %d", b64Str, hexSign, t))
}

// AbsInt gets absolute value
func AbsInt(value int64) uint64 {
	if value < 0 {
		return uint64(-value)
	}
	return uint64(value)
}

func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

// CheckRPCSign checks message signature validation
func CheckRPCSign(data []byte, apiKey string) (body []byte, err error) {
	// params format:
	// base64_encode(body) hex(sign) timestamp_in_s
	params := strings.SplitN(string(data), " ", 3)

	if len(params) != 3 {
		err = ErrUnexceptedFormat
		return
	}

	timestamp, err := strconv.ParseInt(params[2], 10, 64)
	if err != nil {
		return
	}

	// allow 3 minutes error
	if AbsInt(time.Now().UnixNano()/int64(time.Second)-timestamp) > 3*60 {
		err = ErrTimeMismatch
		return
	}

	mac, err := hex.DecodeString(params[1])
	if err != nil {
		return
	}

	if !checkMAC([]byte(params[0]+" "+params[2]), mac, []byte(apiKey)) {
		err = ErrSignature
		return
	}

	body, err = base64.StdEncoding.DecodeString(params[0])
	return
}
