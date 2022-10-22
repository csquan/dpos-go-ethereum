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

package tests

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/params"
)

// Forks table defines supported forks and their chain config.
var Forks = map[string]*params.ChainConfig{
	"Frontier": {
		ChainID: big.NewInt(1),
	},
	"Homestead": {
		ChainID: big.NewInt(1),
	},
	"EIP150": {
		ChainID: big.NewInt(1),
	},
	"EIP158": {
		ChainID: big.NewInt(1),
	},
	"Byzantium": {
		ChainID: big.NewInt(1),
	},
	"Constantinople": {
		ChainID: big.NewInt(1),
	},
	"ConstantinopleFix": {
		ChainID: big.NewInt(1),
	},
	"Istanbul": {
		ChainID: big.NewInt(1),
	},
	"FrontierToHomesteadAt5": {
		ChainID: big.NewInt(1),
	},
	"HomesteadToEIP150At5": {
		ChainID: big.NewInt(1),
	},
	"HomesteadToDaoAt5": {
		ChainID: big.NewInt(1),
	},
	"EIP158ToByzantiumAt5": {
		ChainID: big.NewInt(1),
	},
	"ByzantiumToConstantinopleAt5": {
		ChainID: big.NewInt(1),
	},
	"ByzantiumToConstantinopleFixAt5": {
		ChainID: big.NewInt(1),
	},
	"ConstantinopleFixToIstanbulAt5": {
		ChainID: big.NewInt(1),
	},
	"Berlin": {
		ChainID: big.NewInt(1),
	},
	"BerlinToLondonAt5": {
		ChainID: big.NewInt(1),
	},
	"London": {
		ChainID: big.NewInt(1),
	},
	"ArrowGlacier": {
		ChainID: big.NewInt(1),
	},
	"GrayGlacier": {
		ChainID: big.NewInt(1),
	},
	"Merged": {
		ChainID:                 big.NewInt(1),
		TerminalTotalDifficulty: big.NewInt(0),
	},
}

// Returns the set of defined fork names
func AvailableForks() []string {
	var availableForks []string
	for k := range Forks {
		availableForks = append(availableForks, k)
	}
	sort.Strings(availableForks)
	return availableForks
}

// UnsupportedForkError is returned when a test requests a fork that isn't implemented.
type UnsupportedForkError struct {
	Name string
}

func (e UnsupportedForkError) Error() string {
	return fmt.Sprintf("unsupported fork %q", e.Name)
}
