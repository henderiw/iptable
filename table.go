package iptable

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"sync"

	"go4.org/netipx"
)

type IPTable[T1 any] interface {
	GetIP(addr string) (T1, error)
	ClaimIP(addr string, data T1) error
	UpdateIP(addr string, data T1) error
	ReleaseIP(addr string) error
	GetIndex(index int) (T1, error)
	ClaimIndex(index int, data T1) (string, error)
	UpdateIndex(index int, data T1) error
	ReleaseIndex(index int) error
	ClaimRandomIP(data T1) (string, error)
	IsFree(addr string) bool
}

func NewIPTable[T1 any](from, to netip.Addr) IPTable[T1] {
	ips := numIPs(from, to)
	// Calculate the size of the bitmap
	bitmapSize := int(math.Ceil(float64(ips) / 8))
	return &ipTable[T1]{
		ipRange:    netipx.IPRangeFrom(from, to),
		size:       float64(ips),
		claimedIPs: make([]byte, bitmapSize), // initialize
		table:      make(map[int]T1),
	}
}

type ipTable[T1 any] struct {
	m          sync.RWMutex
	size       float64
	ipRange    netipx.IPRange
	claimedIPs []byte // Bitmap
	table      map[int]T1
}

func (r *ipTable[T1]) validateIP(addr string) (netip.Addr, error) {
	// Parse IP address
	claimIP, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ip address %s is invalid", addr)
	}
	if !r.ipRange.Contains(claimIP) {
		return netip.Addr{}, fmt.Errorf("ip address %s, does not fit in the range from %s to %s", addr, r.ipRange.From().String(), r.ipRange.To().String())
	}
	return claimIP, nil
}

func (r *ipTable[T1]) GetIP(addr string) (T1, error) {
	r.m.RLock()
	defer r.m.RUnlock()
	var zeroT1 T1
	// Validate IP address
	claimIP, err := r.validateIP(addr)
	if err != nil {
		return zeroT1, err
	}
	// Calculate the index in the bitmap
	index := calculateIndex(claimIP, r.ipRange.From())
	return r.getData(index)
}

func (r *ipTable[T1]) ClaimIP(addr string, data T1) error {
	r.m.Lock()
	defer r.m.Unlock()
	// Validate IP address
	claimIP, err := r.validateIP(addr)
	if err != nil {
		return err
	}
	// Calculate the index in the bitmap
	index := calculateIndex(claimIP, r.ipRange.From())

	if !r.isFree(index) {
		return fmt.Errorf("ip address %s is already claimed", addr)
	}
	r.claimIndex(index, data)
	return nil
}

func (r *ipTable[T1]) IsFree(addr string) bool {
	r.m.Lock()
	defer r.m.Unlock()
	// Validate IP address
	claimIP, err := r.validateIP(addr)
	if err != nil {
		return false
	}
	// Calculate the index in the bitmap
	index := calculateIndex(claimIP, r.ipRange.From())

	return r.isFree(index)
}

func (r *ipTable[T1]) UpdateIP(addr string, data T1) error {
	r.m.Lock()
	defer r.m.Unlock()
	// Validate IP address
	claimIP, err := r.validateIP(addr)
	if err != nil {
		return err
	}
	// Calculate the index in the bitmap
	index := calculateIndex(claimIP, r.ipRange.From())

	if r.isFree(index) {
		return fmt.Errorf("cannot update ip address %s data, not claimed", addr)
	}
	return r.UpdateIndex(index, data)
}

func (r *ipTable[T1]) ReleaseIP(s string) error {
	r.m.Lock()
	defer r.m.Unlock()
	// Parse IP address
	claimIP, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("ip address %s is invalid", s)
	}
	if !r.ipRange.Contains(claimIP) {
		return fmt.Errorf("ip address %s, does not fit in the range from %s to %s", s, r.ipRange.From().String(), r.ipRange.To().String())
	}
	// Calculate the index in the bitmap
	index := calculateIndex(claimIP, r.ipRange.From())

	r.releaseIndex(index)
	return nil
}

func (r *ipTable[T1]) GetIndex(index int) (T1, error) {
	r.m.RLock()
	defer r.m.RUnlock()
	var zeroT1 T1

	if r.isFree(index) {
		return zeroT1, fmt.Errorf("ip index %d is not claimed", index)
	}
	return r.getData(index)
}

func (r *ipTable[T1]) ClaimIndex(index int, data T1) (string, error) {
	r.m.Lock()
	defer r.m.Unlock()
	if !r.isFree(index) {
		return "", fmt.Errorf("index %d is already claimed", index)
	}
	// Set the corresponding bit to 1
	r.claimIndex(index, data)
	return calculateIPFromIndex(r.ipRange.From(), index).String(), nil
}

func (r *ipTable[T1]) ReleaseIndex(index int) error {
	r.m.Lock()
	defer r.m.Unlock()
	// Clear the corresponding bit to 0
	r.releaseIndex(index)
	return nil
}

func (r *ipTable[T1]) ClaimRandomIP(data T1) (string, error) {
	r.m.Lock()
	defer r.m.Unlock()
	// Iterate through the bitmap to find an unclaimed IP address
	for i, b := range r.claimedIPs {
		// If all bits are set in the byte, it means there are no free IPs in this byte
		if b == 0xFF {
			continue
		}

		// Iterate through each bit in the byte
		for j := uint(0); j < 8; j++ {
			// Check if the bit is not set (i.e., IP is unclaimed)
			if (b & (1 << (7 - j))) == 0 {
				// Calculate the index of the bit
				bitIndex := i*8 + int(j)

				if bitIndex >= int(r.size) {
					fmt.Println("size", r.size)
					break
				}

				r.claimIndex(bitIndex, data)
				return calculateIPFromIndex(r.ipRange.From(), bitIndex).String(), nil
			}
		}
	}

	return "", errors.New("no free IP addresses available")
}

func (r *ipTable[T1]) UpdateIndex(index int, data T1) error {
	if _, ok := r.table[index]; !ok {
		return fmt.Errorf("data not initialized")
	}
	r.table[index] = data
	return nil
}

func (r *ipTable[T1]) isFree(index int) bool {
	return (r.claimedIPs[index/8] & (1 << uint(7-index%8))) == 0
}

func (r *ipTable[T1]) claimIndex(index int, data T1) {
	r.claimedIPs[index/8] |= 1 << uint(7-index%8)
	r.table[index] = data
}

func (r *ipTable[T1]) releaseIndex(index int) {
	r.claimedIPs[index/8] &^= 1 << uint(7-index%8)
	delete(r.table, index)
}

func (r *ipTable[T1]) getData(index int) (T1, error) {
	data, ok := r.table[index]
	if !ok {
		return data, fmt.Errorf("data not initialized")
	}
	return data, nil
}

func numIPs(startIP, endIP netip.Addr) int {
	// Convert IP addresses to big integers
	start := ipToInt(startIP)
	end := ipToInt(endIP)

	diff := new(big.Int).Sub(end, start)
	return int(diff.Int64()) + 1 // Add 1 to include the start IP
}

func calculateIndex(ip, start netip.Addr) int {
	// Calculate the index in the bitmap
	return int(new(big.Int).Sub(ipToInt(ip), ipToInt(start)).Int64())
}

func ipToInt(ip netip.Addr) *big.Int {
	// Convert IP address to big integer
	bytes := ip.As16()
	ipInt := new(big.Int)
	ipInt.SetBytes(bytes[:])
	return ipInt
}

func calculateIPFromIndex(startIP netip.Addr, index int) netip.Addr {
	// Calculate the IP address corresponding to the index
	ipInt := new(big.Int).Add(ipToInt(startIP), big.NewInt(int64(index)))
	// Convert the big.Int representing the IP address to a byte slice with length 16
	ipBytes := ipInt.Bytes()

	if len(ipBytes) < 16 {
		// If the byte slice is shorter than 16 bytes, pad it with leading zeros
		paddedBytes := make([]byte, 16-len(ipBytes))
		ipBytes = append(paddedBytes, ipBytes...)
	}

	// Convert the byte slice to a [16]byte
	var ip16 [16]byte
	copy(ip16[:], ipBytes)

	if startIP.Is4() {
		return netip.AddrFrom4(netip.AddrFrom16(ip16).As4())
	}
	return netip.AddrFrom16(ip16)
}
