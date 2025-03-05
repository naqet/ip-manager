package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

type IPAllocator struct {
	baseIPNet      *net.IPNet
	lastIPNet      *net.IPNet
	freedBlocks    map[uint8][]string
	reservedIPNets []*net.IPNet
	mu             sync.Mutex
}

func NewIPAllocator(baseBlock string, reservedBlocks []string) (*IPAllocator, error) {
	_, baseIPNet, err := net.ParseCIDR(baseBlock)

	if err != nil {
		return nil, fmt.Errorf("parsing base block failed: %w", err)
	}

	var reservedIPNets []*net.IPNet
	for _, block := range reservedBlocks {
		_, reservedIPNet, err := net.ParseCIDR(block)

		if err != nil {
			return nil, fmt.Errorf("parsing reserved block failed: %w", err)
		}

		reservedIPNets = append(reservedIPNets, reservedIPNet)
	}

	return &IPAllocator{
		baseIPNet:      baseIPNet,
		reservedIPNets: reservedIPNets,
		freedBlocks:    make(map[uint8][]string),
	}, nil
}

func (a *IPAllocator) AllocateCIDR(prefixLen uint8) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	freedBlocks, ok := a.freedBlocks[prefixLen]
	if ok && len(freedBlocks) == 0 {
		allocatedBlocks := freedBlocks[0]
		a.freedBlocks[prefixLen] = freedBlocks[1:]

		return allocatedBlocks, nil
	}
	blockSize := uint32(1 << (32 - prefixLen))

	baseIPInt := ipToInt(a.baseIPNet.IP)
	candidateIpInt := baseIPInt

	if a.lastIPNet != nil {
		candidateIpInt = lastIpInBlock(a.lastIPNet) + 1
	}

	candidateIpInt = alignIpToBlockSize(candidateIpInt, baseIPInt, blockSize)

	for {
		candidateIP := intToIP(candidateIpInt)
		candidateNet := &net.IPNet{
			IP:   candidateIP,
			Mask: net.CIDRMask(int(prefixLen), 32),
		}

		candidateEndIp := intToIP(lastIpInBlock(candidateNet))

		if !a.baseIPNet.Contains(candidateIP) || !a.baseIPNet.Contains(candidateEndIp) {
			return "", fmt.Errorf("allocation exceeds base CIDR range")
		}

		skip := false

		for _, reservedIPNet := range a.reservedIPNets {
			if reservedIPNet.Contains(candidateIP) || reservedIPNet.Contains(candidateEndIp) {
				candidateIpInt = lastIpInBlock(reservedIPNet) + 1
				candidateIpInt = alignIpToBlockSize(candidateIpInt, baseIPInt, blockSize)

				skip = true

				break
			}
		}

		if skip {
			continue
		}

		a.lastIPNet = candidateNet

		return candidateNet.String(), nil
	}
}

func (a *IPAllocator) ReleaseCIDR(block string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(block)

	if err != nil {
		return fmt.Errorf("parsing cidr block failed: %w", err)
	}

	prefixLen, _ := ipNet.Mask.Size()

	if a.freedBlocks[uint8(prefixLen)] == nil {
		a.freedBlocks[uint8(prefixLen)] = []string{}
	}

	a.freedBlocks[uint8(prefixLen)] = append(a.freedBlocks[uint8(prefixLen)], block)

	return nil
}

func ipToInt(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func intToIP(ipInt uint32) net.IP {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, ipInt)
	return buf
}

func lastIpInBlock(block *net.IPNet) uint32 {
	prefixLength, _ := block.Mask.Size()
	capacity := 1 << (32 - prefixLength)

	return ipToInt(block.IP) + uint32(capacity-1)
}

func alignIpToBlockSize(ip, base, size uint32) uint32 {
	offset := ip - base
	roundedOffset := ((offset + size - 1) / size) * size
	return base + roundedOffset
}

func main() {
	fmt.Println("Hello world")
}
