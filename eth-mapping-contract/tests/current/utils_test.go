package current_test

import (
	"fmt"
	"log"
	"strconv"
	"testing"
	"time"
	contract_session "vsc-node/modules/contract/session"
	state_engine "vsc-node/modules/state-processing"
)

var txId int64 = 0

func dumpLogs(t *testing.T, logs map[string]contract_session.LogOutput) {
	t.Helper()
	for name, output := range logs {
		if len(output.Logs) > 0 {
			log.Println("logs for", name)
		}
		for _, log := range output.Logs {
			fmt.Printf("    %s\n", log)
		}
		if len(output.TssOps) > 0 {
			log.Println("tss ops for", name)
		}
		for _, tssOp := range output.TssOps {
			fmt.Printf("    key id: %s, type: %s, args: %s", tssOp.KeyId, tssOp.Type, tssOp.Args)
		}
	}
}

func logStateDiff(t *testing.T, sdm map[string]contract_session.StateDiff) {
	t.Helper()
	for name, sd := range sdm {
		log.Println("state diff for", name)
		for del := range sd.Deletions {
			fmt.Printf("    %*s:\n", 16, del)
		}
		for key, diff := range sd.KeyDiff {
			fmt.Printf("    %*s: %s -> %s\n", 16, key, diff.Previous, diff.Current)
		}
	}
}

func basicSelf(t *testing.T, caller string) *state_engine.TxSelf {
	t.Helper()
	thisTx := txId
	txId++
	return &state_engine.TxSelf{
		TxId:                 strconv.FormatInt(thisTx, 10),
		BlockId:              strconv.FormatInt(thisTx, 10),
		Index:                0,
		OpIndex:              0,
		Timestamp:            time.Now().String(),
		RequiredAuths:        []string{caller},
		RequiredPostingAuths: []string{},
	}
}
