package main

import "C"
import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/elliottech/lighter-go/client/http"
	"github.com/elliottech/lighter-go/signer"
	"github.com/elliottech/lighter-go/types/txtypes"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks"
)

type Session struct {
	privateKey    []byte
	chainId       uint32
	accountIndex  int64
	apiKeyIndex   uint8
	nextNonce     int64
	initNextNonce int64
	keyManager    signer.KeyManager
}

const (
	msgNewLine                 = "\n"
	msgErrorSignatureLength    = "Error signing order: invalid signature length. expected: 80"
	msgErrorSigningTransaction = "Error signing transaction"
	msgErrorNonceMismatch      = "Error nonce mismatch"
	msgErrorWrongSessionIndex  = "Wrong session index"
	msgErrorWrongNonce         = "Wrong nonce"
	msgErrorPanic              = "Recovered from panic"
	msgErrorDecodingPrivateKey = "Error decoding private key"
	msgErrorGettingNextNonce   = "Error getting next nonce"
	msgErrorCreatingKeyManager = "Error creating key manager"
	msgErrorDeadline           = "deadline should be within 7 hours"

	msgGettingNextNonce = "Lighter session getting next nonce..."
	msgGotNextNonce     = "Lighter session got next nonce"
)

var (
	sessions []*Session
)

//export LighterGetOrCreateSession
func LighterGetOrCreateSession(cUrl *C.char, cPrivateKey *C.char, cChainId C.int, cApiKeyIndex C.int, cAccountIndex C.longlong) (ret C.int) {
	runtime.LockOSThread()

	ret = C.int(-1)
	defer func() {
		if r := recover(); r != nil {
			//fmt.Printf("Recovered from panic: %v\n", r)
			_, _ = os.Stderr.Write([]byte(msgErrorPanic))
			_, _ = os.Stderr.Write([]byte(msgNewLine))
			ret = C.int(-1)
		}
	}()

	url := C.GoString(cUrl)
	privateKeyString := C.GoString(cPrivateKey)
	chainId := uint32(cChainId)
	apiKeyIndex := uint8(cApiKeyIndex)
	accountIndex := int64(cAccountIndex)

	privateKey, err := hex.DecodeString(privateKeyString)
	if err != nil {
		//fmt.Printf("Error decoding private key: %v\n", err)
		_, _ = os.Stderr.Write([]byte(msgErrorDecodingPrivateKey))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}

	for i, session := range sessions {
		if bytes.Equal(session.privateKey, privateKey) {
			ret = C.int(i)
			return
		}
	}

	// for debug
	//if isDebug {
	//	if err = CreateClient(url, privateKeyString, chainId, apiKeyIndex, accountIndex); err != nil {
	//		fmt.Printf("Error creating client: %v\n", err)
	//		return
	//	}
	//}

	//fmt.Printf("Lighter session getting next nonce...\n")
	_, _ = os.Stderr.Write([]byte(msgGettingNextNonce))
	_, _ = os.Stderr.Write([]byte(msgNewLine))
	httpClient := http.NewClient(url)
	nextNonce, err := httpClient.GetNextNonce(accountIndex, apiKeyIndex)
	if err != nil {
		//fmt.Printf("Error getting next nonce: %v\n", err)
		_, _ = os.Stderr.Write([]byte(msgErrorGettingNextNonce))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	//fmt.Printf("Lighter session next nonce: %v\n", nextNonce)
	_, _ = os.Stderr.Write([]byte(msgGotNextNonce))
	_, _ = os.Stderr.Write([]byte(msgNewLine))

	keyManager, err := signer.NewKeyManager(privateKey)
	if err != nil {
		//fmt.Printf("Error creating key manager: %v\n", err)
		_, _ = os.Stderr.Write([]byte(msgErrorCreatingKeyManager))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}

	sessions = append(sessions, &Session{
		privateKey:    privateKey,
		chainId:       chainId,
		accountIndex:  accountIndex,
		apiKeyIndex:   apiKeyIndex,
		nextNonce:     nextNonce,
		initNextNonce: nextNonce,
		keyManager:    keyManager,
	})

	ret = C.int(len(sessions) - 1)
	return
}

//export LighterGetNextNonce
func LighterGetNextNonce(cSid C.int) (ret C.longlong) {
	runtime.LockOSThread()

	ret = C.longlong(-1)
	sid := int(cSid)
	if sid < 0 || sid >= len(sessions) {
		_, _ = os.Stderr.Write([]byte(msgErrorWrongSessionIndex))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	session := sessions[sid]
	if session.nextNonce < session.initNextNonce {
		_, _ = os.Stderr.Write([]byte(msgErrorWrongNonce))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	ret = C.longlong(session.nextNonce)
	return
}

//export LighterAdvanceNextNonce
func LighterAdvanceNextNonce(cSid C.int) (ret C.longlong) {
	runtime.LockOSThread()

	ret = C.longlong(-1)
	sid := int(cSid)
	if sid < 0 || sid >= len(sessions) {
		_, _ = os.Stderr.Write([]byte(msgErrorWrongSessionIndex))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	session := sessions[sid]
	if session.nextNonce < session.initNextNonce {
		_, _ = os.Stderr.Write([]byte(msgErrorWrongNonce))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	session.nextNonce++
	ret = C.longlong(session.nextNonce)
	return
}

//export LighterRewindNextNonce
func LighterRewindNextNonce(cSid C.int) (ret C.longlong) {
	runtime.LockOSThread()

	ret = C.longlong(-1)
	sid := int(cSid)
	if sid < 0 || sid >= len(sessions) {
		_, _ = os.Stderr.Write([]byte(msgErrorWrongSessionIndex))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	session := sessions[sid]
	session.nextNonce--
	if session.nextNonce < session.initNextNonce {
		_, _ = os.Stderr.Write([]byte(msgErrorWrongNonce))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	ret = C.longlong(session.nextNonce)
	return
}

//export LighterSignCreateOrder
func LighterSignCreateOrder(cSid C.int, cElems *C.char, cSig *C.char, cMarketIndex C.int, cClientOrderIndex C.longlong, cBaseAmount C.longlong, cPrice C.int, cIsAsk C.int, cOrderType C.int, cTimeInForce C.int, cReduceOnly C.int, cTriggerPrice C.int, cOrderExpiry C.longlong, cNonce C.longlong, cExpiredAt C.longlong) (ret C.int) {
	runtime.LockOSThread()

	ret = C.int(-1)
	sid := int(cSid)
	elems := (*[16]g.Element)(unsafe.Pointer(cElems))[:]
	marketIndex := int16(cMarketIndex)
	clientOrderIndex := int64(cClientOrderIndex)
	baseAmount := int64(cBaseAmount)
	price := uint32(cPrice)
	isAsk := uint8(cIsAsk)
	orderType := uint8(cOrderType)
	timeInForce := uint8(cTimeInForce)
	reduceOnly := uint8(cReduceOnly)
	triggerPrice := uint32(cTriggerPrice)
	orderExpiry := int64(cOrderExpiry)
	nonce := int64(cNonce)
	expiredAt := int64(cExpiredAt)

	session := sessions[sid]
	if nonce != session.nextNonce {
		_, _ = os.Stderr.Write([]byte(msgErrorNonceMismatch))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}

	elems[0] = g.FromUint32(session.chainId)
	elems[1] = g.FromUint32(txtypes.TxTypeL2CreateOrder)
	elems[2] = g.FromInt64(nonce)
	elems[3] = g.FromInt64(expiredAt)

	elems[4] = g.FromInt64(session.accountIndex)
	elems[5] = g.FromUint32(uint32(session.apiKeyIndex))
	elems[6] = g.FromUint32(uint32(marketIndex))
	elems[7] = g.FromInt64(clientOrderIndex)
	elems[8] = g.FromInt64(baseAmount)
	elems[9] = g.FromUint32(price)
	elems[10] = g.FromUint32(uint32(isAsk))
	elems[11] = g.FromUint32(uint32(orderType))
	elems[12] = g.FromUint32(uint32(timeInForce))
	elems[13] = g.FromUint32(uint32(reduceOnly))
	elems[14] = g.FromUint32(triggerPrice)
	elems[15] = g.FromInt64(orderExpiry)

	hash := p2.HashToQuinticExtension(elems).ToLittleEndianBytes()
	//fmt.Printf("LighterSignCreateOrder.Hash: %s\n", hex.EncodeToString(hash))
	signature, err := session.keyManager.Sign2(hash)
	if err != nil {
		_, _ = os.Stderr.Write([]byte(msgErrorSigningTransaction))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	if len(signature) != 80 {
		_, _ = os.Stderr.Write([]byte(msgErrorSignatureLength))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}

	// fmt.Printf("Sig: %d %s\n", len(signature), base64.StdEncoding.EncodeToString(signature))
	dst := unsafe.Slice((*byte)(unsafe.Pointer(cSig)), 80)
	copy(dst, signature)
	ret = C.int(0)
	return
}

//export LighterSignCancelOrder
func LighterSignCancelOrder(cSid C.int, cElems *C.char, cSig *C.char, cMarketIndex C.int, cOrderIndex C.longlong, cNonce C.longlong, cExpiredAt C.longlong) (ret C.int) {
	runtime.LockOSThread()

	ret = C.int(-1)
	sid := int(cSid)
	elems := (*[8]g.Element)(unsafe.Pointer(cElems))[:]
	marketIndex := int16(cMarketIndex)
	orderIndex := int64(cOrderIndex)
	nonce := int64(cNonce)
	expiredAt := int64(cExpiredAt)

	session := sessions[sid]
	if nonce != session.nextNonce {
		_, _ = os.Stderr.Write([]byte(msgErrorNonceMismatch))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}

	// for debug
	//if isDebug {
	//	err, debug := SignCancelOrder(marketIndex, orderIndex, nonce, expiredAt)
	//	if err != nil {
	//		fmt.Printf("Error signing order: %v\n", err)
	//		return
	//	}
	//	fmt.Printf("Debug: %v\n", debug)
	//}

	elems[0] = g.FromUint32(session.chainId)
	elems[1] = g.FromUint32(txtypes.TxTypeL2CancelOrder)
	elems[2] = g.FromInt64(nonce)
	elems[3] = g.FromInt64(expiredAt)

	elems[4] = g.FromInt64(session.accountIndex)
	elems[5] = g.FromUint32(uint32(session.apiKeyIndex))
	elems[6] = g.FromUint32(uint32(marketIndex))
	elems[7] = g.FromInt64(orderIndex)

	hash := p2.HashToQuinticExtension(elems).ToLittleEndianBytes()
	//if isDebug {
	//	fmt.Printf("LighterSignCancelOrder.Hash: %s\n", hex.EncodeToString(hash))
	//}
	signature, err := session.keyManager.Sign2(hash)
	if err != nil {
		_, _ = os.Stderr.Write([]byte(msgErrorSigningTransaction))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	if len(signature) != 80 {
		_, _ = os.Stderr.Write([]byte(msgErrorSignatureLength))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	// fmt.Printf("Sig: %d %s\n", len(signature), base64.StdEncoding.EncodeToString(signature))
	dst := unsafe.Slice((*byte)(unsafe.Pointer(cSig)), 80)
	copy(dst, signature)
	ret = C.int(0)
	return
}

//export LighterGetAuthToken
func LighterGetAuthToken(cSid C.int, cSig *C.char, cDeadline C.longlong) (ret C.int) {
	runtime.LockOSThread()

	ret = C.int(-1)
	sid := int(cSid)
	deadline := time.Unix(int64(cDeadline), 0)

	session := sessions[sid]
	message := fmt.Sprintf("%v:%v:%v", deadline.Unix(), session.accountIndex, session.apiKeyIndex)

	msgInField, err := g.ArrayFromCanonicalLittleEndianBytes([]byte(message))
	if err != nil {
		fmt.Println("error getting msg in field")
		return
	}

	msgHash := p2.HashToQuinticExtension(msgInField).ToLittleEndianBytes()

	signature, err := session.keyManager.Sign2(msgHash)
	if err != nil {
		_, _ = os.Stderr.Write([]byte(msgErrorSigningTransaction))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	if len(signature) != 80 {
		_, _ = os.Stderr.Write([]byte(msgErrorSignatureLength))
		_, _ = os.Stderr.Write([]byte(msgNewLine))
		return
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(cSig)), 80)
	copy(dst, signature)
	ret = C.int(0)
	return
}

func main() {}
