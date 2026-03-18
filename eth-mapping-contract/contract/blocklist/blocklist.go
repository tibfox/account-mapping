package blocklist

import (
	"encoding/hex"
	"errors"
	"math"
	"strconv"

	"eth-mapping-contract/contract/constants"
	ce "eth-mapping-contract/contract/contracterrors"
	"eth-mapping-contract/sdk"
)

// ETH block headers are RLP-encoded and variable length.
// Unlike BTC's fixed 80-byte headers, each ETH header is stored
// individually as a hex-encoded RLP blob.

//tinyjson:json
type AddBlocksParams struct {
	Blocks []string `json:"blocks"` // each entry is a hex-encoded RLP header
}

//tinyjson:json
type SeedBlocksParams struct {
	BlockHeader string `json:"block_header"`
	BlockHeight uint32 `json:"block_height"`
}

const LastHeightKey = "lsthgt"

var ErrorLastHeightDNE = errors.New("last height does not exist")

var ErrorSequenceIncorrect = errors.New("block sequence incorrect")

func LastHeightFromState() (uint32, error) {
	lastHeightString := sdk.StateGetObject(LastHeightKey)
	if *lastHeightString == "" {
		return 0, ErrorLastHeightDNE
	}
	lastHeight, err := strconv.ParseUint(*lastHeightString, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(lastHeight), nil
}

func LastHeightToState(lastHeight uint32) {
	sdk.StateSetObject(LastHeightKey, strconv.FormatUint(uint64(lastHeight), 10))
}

// HandleAddBlocks stores RLP-encoded ETH block headers sequentially.
// Each header in the slice is a hex-encoded RLP blob.
func HandleAddBlocks(headers []string, networkMode string) (uint32, uint32, error) {
	lastHeight, err := LastHeightFromState()
	if err != nil {
		return 0, 0, ce.WrapContractError(ce.ErrStateAccess, err)
	}
	initialLastHeight := lastHeight

	for _, headerHex := range headers {
		// Validate hex encoding
		_, err := hex.DecodeString(headerHex)
		if err != nil {
			return 0, 0, ce.WrapContractError(ce.ErrInvalidHex, err)
		}

		if lastHeight == math.MaxUint32 {
			return 0, 0, ce.NewContractError(ce.ErrArithmetic, "block height exceeds max possible")
		}
		blockHeight := lastHeight + 1

		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatUint(uint64(blockHeight), 10),
			headerHex,
		)
		lastHeight = blockHeight
	}

	return lastHeight, lastHeight - initialLastHeight, nil
}

func HandleSeedBlocks(seedParams SeedBlocksParams, allowReseed bool) (uint32, error) {
	lastHeight, err := LastHeightFromState()
	if err != nil {
		if err != ErrorLastHeightDNE {
			return 0, err
		}
	} else if !allowReseed {
		return 0, ce.NewContractError(ce.ErrInitialization, "blocks already seeded last height "+strconv.FormatUint(uint64(lastHeight), 10))
	}

	if lastHeight == 0 || lastHeight < seedParams.BlockHeight {
		sdk.StateSetObject(
			constants.BlockPrefix+strconv.FormatInt(int64(seedParams.BlockHeight), 10),
			seedParams.BlockHeader,
		)
		sdk.StateSetObject(LastHeightKey, strconv.FormatInt(int64(seedParams.BlockHeight), 10))
		return seedParams.BlockHeight, nil
	}

	return 0, ce.NewContractError(
		ce.ErrInput,
		"last height >= input block height. last height: "+strconv.FormatUint(uint64(lastHeight), 10),
	)
}
