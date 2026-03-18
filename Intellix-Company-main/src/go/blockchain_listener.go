// Intellix Blockchain Listener — Go 1.22
// ========================================
// Real-time Ethereum block & transaction monitor.
// Subscribes to new blocks, scans for Intellix vault
// transactions, runs fraud pre-checks, and emits events
// to downstream services via channels.
//
// Run:
//   go mod tidy
//   go run blockchain_listener.go
//
// In production this connects to a real Ethereum node via WebSocket.
// For demo it runs a local block simulator.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────

// Block represents an Ethereum block header summary
type Block struct {
	Number    uint64    `json:"number"`
	Hash      string    `json:"hash"`
	ParentHash string   `json:"parentHash"`
	Timestamp time.Time `json:"timestamp"`
	GasUsed   uint64   `json:"gasUsed"`
	GasLimit  uint64   `json:"gasLimit"`
	TxCount   int      `json:"txCount"`
}

// Transaction represents an on-chain transaction
type Transaction struct {
	Hash      string   `json:"hash"`
	BlockNum  uint64   `json:"block"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Value     *big.Int `json:"value"`  // in wei (1 ETH = 1e18 wei)
	GasPrice  *big.Int `json:"gasPrice"`
	GasUsed   uint64   `json:"gasUsed"`
	Input     []byte   `json:"input"`
	Status    uint8    `json:"status"` // 1 = success, 0 = reverted
}

// ParsedTransfer is an Intellix-relevant transfer decoded from a tx
type ParsedTransfer struct {
	TxHash      string    `json:"txHash"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	AmountWei   *big.Int  `json:"amountWei"`
	AmountETH   float64   `json:"amountETH"`
	AmountUSD   float64   `json:"amountUSD"`
	TokenSymbol string    `json:"tokenSymbol"`
	Block       uint64    `json:"block"`
	Timestamp   time.Time `json:"timestamp"`
	IsIntellix  bool      `json:"isIntellix"`
}

// FraudPreCheck is a lightweight on-chain risk assessment
type FraudPreCheck struct {
	TxHash    string  `json:"txHash"`
	RiskScore float64 `json:"riskScore"`
	Flags     []string `json:"flags"`
	Action    string  `json:"action"` // pass, flag, block
}

// EventType for downstream services
type EventType string

const (
	EventNewBlock    EventType = "block.new"
	EventTransfer    EventType = "transfer.detected"
	EventFraudFlag   EventType = "fraud.flagged"
	EventHighValue   EventType = "transfer.high_value"
)

// Event wraps any blockchain event
type Event struct {
	Type      EventType   `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Payload   interface{} `json:"payload"`
}

// ─────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────

const (
	ETH_DECIMALS    = 1e18
	ETH_PRICE_USD   = 3502.18
	HIGH_VALUE_USD  = 50_000.0

	// Intellix vault contract address (mainnet)
	INTELLIX_VAULT  = "0xIntellix1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
)

var (
	// Known Intellix user wallets (in production: fetched from DB)
	KNOWN_WALLETS = map[string]string{
		"0xUSR001wallet": "USR001",
		"0xUSR002wallet": "USR002",
		"0xUSR003wallet": "USR003",
		"0xVAULT_BTC":   "VAULT",
		"0xPOOL_UNI":    "DEFI",
	}

	// High-risk destination patterns
	HIGH_RISK_PATTERNS = []string{
		"0xCAYMAN",
		"0xMIXER",
		"0xTORNADO",
		"0xANON",
	}
)

// ─────────────────────────────────────────────
// FRAUD PRE-CHECKER
// ─────────────────────────────────────────────

type FraudPreChecker struct {
	mu        sync.RWMutex
	blacklist map[string]bool
	checked   atomic.Uint64
}

func NewFraudPreChecker() *FraudPreChecker {
	return &FraudPreChecker{
		blacklist: map[string]bool{
			"0xCAYMAN99":   true,
			"0xMIXER123":   true,
			"0xTORNADO456": true,
		},
	}
}

func (f *FraudPreChecker) Check(tx *ParsedTransfer) *FraudPreCheck {
	f.checked.Add(1)

	result := &FraudPreCheck{
		TxHash:    tx.TxHash,
		RiskScore: 0.01,
		Flags:     []string{},
		Action:    "pass",
	}

	f.mu.RLock()
	isBlacklisted := f.blacklist[tx.To]
	f.mu.RUnlock()

	if isBlacklisted {
		result.RiskScore += 0.75
		result.Flags = append(result.Flags, "blacklisted_destination")
	}

	// Check for high-risk patterns
	for _, pattern := range HIGH_RISK_PATTERNS {
		if len(tx.To) >= len(pattern) && tx.To[:len(pattern)] == pattern {
			result.RiskScore += 0.40
			result.Flags = append(result.Flags, "high_risk_pattern:"+pattern)
			break
		}
	}

	if tx.AmountUSD > HIGH_VALUE_USD {
		result.RiskScore += 0.10
		result.Flags = append(result.Flags, fmt.Sprintf("high_value:$%.0f", tx.AmountUSD))
	}

	if tx.AmountUSD > 500_000 {
		result.RiskScore += 0.20
		result.Flags = append(result.Flags, "critical_value")
	}

	// Cap at 1.0
	if result.RiskScore > 1.0 {
		result.RiskScore = 1.0
	}

	switch {
	case result.RiskScore >= 0.85:
		result.Action = "block"
	case result.RiskScore >= 0.50:
		result.Action = "flag"
	default:
		result.Action = "pass"
	}

	return result
}

func (f *FraudPreChecker) AddToBlacklist(address string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blacklist[address] = true
}

// ─────────────────────────────────────────────
// BLOCK SIMULATOR (replaces real Ethereum WS in demo)
// ─────────────────────────────────────────────

type BlockSimulator struct {
	currentBlock uint64
	blockChan    chan *Block
	txChan       chan *Transaction
	stopCh       chan struct{}
}

func NewBlockSimulator(startBlock uint64) *BlockSimulator {
	return &BlockSimulator{
		currentBlock: startBlock,
		blockChan:    make(chan *Block, 10),
		txChan:       make(chan *Transaction, 100),
		stopCh:       make(chan struct{}),
	}
}

func (s *BlockSimulator) generateHash(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return "0x" + hex.EncodeToString(h[:])
}

func (s *BlockSimulator) generateAddress(seed int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("addr%d", seed)))
	return "0x" + hex.EncodeToString(h[:20])
}

func (s *BlockSimulator) Start() {
	go func() {
		ticker := time.NewTicker(2 * time.Second) // ~2s block time for demo
		defer ticker.Stop()

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.currentBlock++
				block := &Block{
					Number:    s.currentBlock,
					Hash:      s.generateHash(fmt.Sprintf("block%d", s.currentBlock)),
					ParentHash: s.generateHash(fmt.Sprintf("block%d", s.currentBlock-1)),
					Timestamp: time.Now(),
					GasUsed:   uint64(rand.Int63n(15_000_000)),
					GasLimit:  30_000_000,
					TxCount:   rand.Intn(250) + 50,
				}
				s.blockChan <- block

				// Generate 1-5 interesting transactions per block
				numTxns := rand.Intn(4) + 1
				go s.generateTransactions(block, numTxns)
			}
		}
	}()
}

func (s *BlockSimulator) generateTransactions(block *Block, count int) {
	intellixAddresses := []string{
		"0xUSR001wallet", "0xUSR002wallet", "0xVAULT_BTC", "0xPOOL_UNI",
		INTELLIX_VAULT,
	}

	// Occasionally include a suspicious destination
	suspiciousAddresses := []string{"0xCAYMAN99", "0xANON9821", "0xMIXER123"}

	for i := 0; i < count; i++ {
		fromIdx := rand.Intn(len(intellixAddresses))
		var toAddr string
		if rand.Float64() < 0.15 { // 15% chance of suspicious dest
			toAddr = suspiciousAddresses[rand.Intn(len(suspiciousAddresses))]
		} else {
			toAddr = s.generateAddress(rand.Int())
		}

		// Value in wei: between 0.01 ETH and 50 ETH
		ethAmount := (rand.Float64()*49.99 + 0.01)
		valueWei := new(big.Int).SetInt64(int64(ethAmount * ETH_DECIMALS))

		txHash := s.generateHash(fmt.Sprintf("tx%d-%d-%d", block.Number, i, time.Now().UnixNano()))

		tx := &Transaction{
			Hash:     txHash,
			BlockNum: block.Number,
			From:     intellixAddresses[fromIdx],
			To:       toAddr,
			Value:    valueWei,
			GasPrice: big.NewInt(20_000_000_000), // 20 gwei
			GasUsed:  21_000,
			Status:   1,
		}
		s.txChan <- tx
	}
}

func (s *BlockSimulator) Stop() {
	close(s.stopCh)
}

// ─────────────────────────────────────────────
// BLOCKCHAIN LISTENER
// ─────────────────────────────────────────────

type Listener struct {
	simulator    *BlockSimulator
	fraudChecker *FraudPreChecker
	eventChan    chan Event

	// Metrics
	blocksProcessed  atomic.Uint64
	txnsProcessed    atomic.Uint64
	fraudsFlagged    atomic.Uint64
	highValueDetected atomic.Uint64

	wg sync.WaitGroup
}

func NewListener() *Listener {
	return &Listener{
		simulator:    NewBlockSimulator(20_000_000),
		fraudChecker: NewFraudPreChecker(),
		eventChan:    make(chan Event, 1000),
	}
}

func (l *Listener) parseTransaction(tx *Transaction) *ParsedTransfer {
	// Convert wei to ETH
	ethWei := new(big.Float).SetInt(tx.Value)
	divisor := new(big.Float).SetFloat64(ETH_DECIMALS)
	ethAmount, _ := new(big.Float).Quo(ethWei, divisor).Float64()
	usdAmount := ethAmount * ETH_PRICE_USD

	_, isIntellix := KNOWN_WALLETS[tx.From]
	if !isIntellix {
		_, isIntellix = KNOWN_WALLETS[tx.To]
	}
	if tx.To == INTELLIX_VAULT || tx.From == INTELLIX_VAULT {
		isIntellix = true
	}

	return &ParsedTransfer{
		TxHash:      tx.Hash,
		From:        tx.From,
		To:          tx.To,
		AmountWei:   tx.Value,
		AmountETH:   ethAmount,
		AmountUSD:   usdAmount,
		TokenSymbol: "ETH",
		Block:       tx.BlockNum,
		Timestamp:   time.Now(),
		IsIntellix:  isIntellix,
	}
}

func (l *Listener) processBlock(ctx context.Context, block *Block) {
	defer l.wg.Done()

	l.blocksProcessed.Add(1)

	l.eventChan <- Event{
		Type:      EventNewBlock,
		Timestamp: time.Now(),
		Payload:   block,
	}
}

func (l *Listener) processTransaction(ctx context.Context, tx *Transaction) {
	defer l.wg.Done()

	parsed := l.parseTransaction(tx)
	l.txnsProcessed.Add(1)

	// Only process Intellix-relevant or high-value transactions
	if !parsed.IsIntellix && parsed.AmountUSD < 10_000 {
		return
	}

	l.eventChan <- Event{
		Type:      EventTransfer,
		Timestamp: time.Now(),
		Payload:   parsed,
	}

	// High value alert
	if parsed.AmountUSD >= HIGH_VALUE_USD {
		l.highValueDetected.Add(1)
		l.eventChan <- Event{
			Type:      EventHighValue,
			Timestamp: time.Now(),
			Payload:   parsed,
		}
	}

	// Fraud pre-check
	fraud := l.fraudChecker.Check(parsed)
	if fraud.Action != "pass" {
		l.fraudsFlagged.Add(1)
		l.eventChan <- Event{
			Type:      EventFraudFlag,
			Timestamp: time.Now(),
			Payload:   fraud,
		}
	}
}

func (l *Listener) Watch(ctx context.Context) {
	l.simulator.Start()
	defer l.simulator.Stop()

	fmt.Println("  ● Blockchain listener started — watching for Intellix transactions")

	for {
		select {
		case <-ctx.Done():
			l.wg.Wait()
			fmt.Println("  ● Listener stopped gracefully")
			return

		case block := <-l.simulator.blockChan:
			l.wg.Add(1)
			go l.processBlock(ctx, block)

		case tx := <-l.simulator.txChan:
			l.wg.Add(1)
			go l.processTransaction(ctx, tx)
		}
	}
}

func (l *Listener) Metrics() map[string]uint64 {
	return map[string]uint64{
		"blocks_processed":   l.blocksProcessed.Load(),
		"txns_processed":     l.txnsProcessed.Load(),
		"frauds_flagged":     l.fraudsFlagged.Load(),
		"high_value_alerts":  l.highValueDetected.Load(),
	}
}

// ─────────────────────────────────────────────
// EVENT CONSUMER
// ─────────────────────────────────────────────

func consumeEvents(ctx context.Context, events <-chan Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			switch event.Type {
			case EventNewBlock:
				block := event.Payload.(*Block)
				fmt.Printf("  ⬡ Block #%d | %d txns | gas: %d/%d\n",
					block.Number, block.TxCount, block.GasUsed, block.GasLimit)

			case EventTransfer:
				t := event.Payload.(*ParsedTransfer)
				intellixTag := ""
				if t.IsIntellix {
					intellixTag = " [INTELLIX]"
				}
				fmt.Printf("  ↳ Transfer%s %.4f ETH ($%.0f) %s → %s...\n",
					intellixTag, t.AmountETH, t.AmountUSD,
					t.From[:12], t.To[:12])

			case EventHighValue:
				t := event.Payload.(*ParsedTransfer)
				fmt.Printf("  ★ HIGH VALUE: $%.0f ETH — %s\n", t.AmountUSD, t.TxHash[:18])

			case EventFraudFlag:
				f := event.Payload.(*FraudPreCheck)
				b, _ := json.Marshal(f.Flags)
				fmt.Printf("  ⚠ FRAUD [%s] score=%.3f flags=%s tx=%s...\n",
					f.Action, f.RiskScore, string(b), f.TxHash[:18])
			}
		}
	}
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

func main() {
	fmt.Println(string([]byte{0xe2, 0x95, 0x90}) + "×60")
	fmt.Println("  INTELLIX BLOCKCHAIN LISTENER — Go 1.22")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Printf("  ETH Price  : $%.2f\n", ETH_PRICE_USD)
	fmt.Printf("  High-value : >$%.0f\n\n", HIGH_VALUE_USD)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	listener := NewListener()

	// Start event consumer in background
	go consumeEvents(ctx, listener.eventChan)

	// Print metrics every 5 seconds
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m := listener.Metrics()
				fmt.Printf("\n  ── Metrics: blocks=%d txns=%d frauds=%d high_value=%d\n\n",
					m["blocks_processed"], m["txns_processed"],
					m["frauds_flagged"], m["high_value_alerts"])
			}
		}
	}()

	// Watch blocks until context expires
	listener.Watch(ctx)

	// Final metrics
	fmt.Println("\n  Final metrics:")
	for k, v := range listener.Metrics() {
		fmt.Printf("  %-25s %d\n", k+":", v)
	}
}
