package capture

import (
	"sync"
	"sync/atomic"
	"time"
)

type Statistics struct {
	StartTime         time.Time
	TotalPackets      atomic.Uint64
	TotalBytes        atomic.Uint64
	PacketsByProtocol sync.Map // map[string]uint64
}

var stats Statistics

func init() {
	stats = Statistics{
		StartTime: time.Now(),
	}
}

func incrementProtocolCount(protocol string) {
	value, _ := stats.PacketsByProtocol.LoadOrStore(protocol, uint64(0))
	stats.PacketsByProtocol.Store(protocol, value.(uint64)+1)
}

func GetStatistics() Statistics {
	return stats
}

func updateStats(bytes uint64) {
	stats.TotalPackets.Add(1)
	stats.TotalBytes.Add(bytes)
}
