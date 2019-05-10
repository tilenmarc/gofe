/*
 * Copyright (c) 2018 XLAB d.o.o
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample

import (
	"math/big"

	emmy "github.com/xlab-si/emmy/crypto/common"
	"math/rand"
)

// UniformRange samples random values from the interval [min, max).
type UniformRange struct {
	min *big.Int
	max *big.Int
}

// NewUniformRange returns an instance of the UniformRange sampler.
// It accepts lower and upper bounds on the sampled values.
func NewUniformRange(min, max *big.Int) *UniformRange {
	return &UniformRange{
		min: min,
		max: max,
	}
}

// UniformRange samples random values from the interval [min, max).
func (u *UniformRange) Sample() (*big.Int, error) {
	return emmy.GetRandomIntFromRange(u.min, u.max)
}

// Uniform samples random values from the interval [0, max).
type Uniform struct {
	UniformRange
}

// NewUniform returns an instance of the Uniform sampler.
// It accepts an upper bound on the sampled values.
func NewUniform(max *big.Int) *UniformRange {
	return NewUniformRange(big.NewInt(0), max)
}

func (u *Uniform) Sample() (*big.Int, error) {
	return emmy.GetRandomInt(u.max), nil
}

// Bit samples a single random bit (value 0 or 1).
type Bit struct {
	Uniform
}

// NewBit returns an instance of Bit sampler.
func NewBit() *UniformRange {
	return NewUniform(big.NewInt(2))
}

// PseudoUniform samples random values from the interval [0, max).
type PseudoUniform struct {
	max *big.Int
	rnd *rand.Rand
}

// NewPseudoUniform returns an instance of the PseudoUniform sampler.
// It accepts upper bounds on the sampled values.
func NewPseudoUniform(max *big.Int) *PseudoUniform {
	source := rand.NewSource(emmy.GetRandomInt(new(big.Int).Exp(big.NewInt(2), big.NewInt(63), nil)).Int64())
	rnd := rand.New(source)
	return &PseudoUniform{
		max: max,
		rnd: rnd,
	}
}

func (u *PseudoUniform) Sample() (*big.Int, error) {
	return new(big.Int).Rand(u.rnd, u.max), nil
}