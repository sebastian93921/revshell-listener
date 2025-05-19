package main

import (
	"math/rand"
	"time"
)

var PWNCommand string

func init() {
	// Initialize random seed
	rand.Seed(time.Now().UnixNano())
	
	// Generate random 5 uppercase characters
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, 5)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	PWNCommand = string(result)
} 