package main

import (
	"fmt"
	"sort"
	"sync"
)

type SessionManager struct {
	sessions map[int]*Socket
	lock     sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[int]*Socket),
	}
}

func (sm *SessionManager) Add(id int, socket *Socket) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	sm.sessions[id] = socket
}

func (sm *SessionManager) Get(id int) (*Socket, bool) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	socket, ok := sm.sessions[id]
	return socket, ok
}

func (sm *SessionManager) Remove(id int) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	if socket, ok := sm.sessions[id]; ok {
		socket.isClosed = true
		if socket.con != nil {
			socket.con.Close()
		}
		delete(sm.sessions, id)
	}
}

func (sm *SessionManager) Count() int {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	return len(sm.sessions)
}

func (sm *SessionManager) List() {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	// Sort keys to print in order
	keys := make([]int, 0, len(sm.sessions))
	for k := range sm.sessions {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	fmt.Println("--------------------------------------------------------------------->")
	for _, id := range keys {
		fmt.Println(sm.sessions[id].status())
	}
	fmt.Println("<---------------------------------------------------------------------")
}

func (sm *SessionManager) Rename(id int, name string) bool {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	if socket, ok := sm.sessions[id]; ok {
		socket.Name = name
		return true
	}
	return false
}
