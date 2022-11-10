// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/ethereum/go-ethereum/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Ethereum network.
var MainnetBootnodes = []string{
	// Ethereum Foundation Go Bootnodes
	"enode://e0b44770ddbf806a446c84814f2a43a8284e6ffdd0175b76182e3ca94ef27b4e55fdcb7f475af0056458a0eb3e1b99f49391fcd3f7357b2c71f108e2261171ef@18.163.116.227:30303",
	"enode://5c83554ea0685f677fd1a6902ff51ee60216b70caba362397c918d8df3d5d7b002a2ff0a59878e5670a280f069eef6b471de8bfba91fd0d09a5bfbbefb292aa2@34.201.5.122:30303",
	"enode://150bd5633e11b89805de8fd6368b7c0e8868564ff3bc9f8449b9f3cdc1b236d4868f6e965e0f2727b623ce497f4f72f7eda2c310eb8428eb1caea9bfd56ea69c@52.221.213.5:30303",
}

const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// information.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	var net string
	switch genesis {
	case MainnetGenesisHash:
		net = "harmony"
	default:
		return ""
	}
	return dnsPrefix + protocol + "." + net + ".ethdisco.net"
}
