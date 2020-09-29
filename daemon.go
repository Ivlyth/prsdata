package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
)

func startDaemon() error {
	// open a listener to which the child process will connect when
	// it is ready to confirm that it has successfully started
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("opening listener for success confirmation: %v", err)
	}
	defer ln.Close()

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Args = append(cmd.Args, "--pingback", ln.Addr().String())

	stdinpipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %v", err)
	}
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr

	// generate the random bytes we'll send to the child process
	expect := make([]byte, 32)
	_, err = rand.Read(expect)
	if err != nil {
		return fmt.Errorf("generating random confirmation bytes: %v", err)
	}

	// begin writing the confirmation bytes to the child's
	// stdin; use a goroutine since the child hasn't been
	// started yet, and writing synchronously would result
	// in a deadlock
	go func() {
		stdinpipe.Write(expect)
		stdinpipe.Close()
	}()

	// start the process
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("starting prsdata process: %v", err)
	}

	// there are two ways we know we're done: either
	// the process will connect to our listener, or
	// it will exit with an error
	success, exit := make(chan struct{}), make(chan error)

	// in one goroutine, we await the success of the child process
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					logger.Errorln(fmt.Sprintf("use of closed network connection"))
				}
				break
			}
			err = handlePingbackConn(conn, expect)
			if err == nil {
				close(success)
				break
			}
			logger.Errorln(fmt.Sprintf("error when handle ping back connection: %s", err))
		}
	}()

	// in another goroutine, we await the failure of the child process
	go func() {
		err := cmd.Wait() // don't send on this line! Wait blocks, but send starts before it unblocks
		exit <- err       // sending on separate line ensures select won't trigger until after Wait unblocks
	}()

	// when one of the goroutines unblocks, we're done and can exit
	select {
	case <-success:
		fmt.Printf("Successfully started prsdata (pid=%d) - prsdata is running in the background\n", cmd.Process.Pid)
	case err := <-exit:
		return fmt.Errorf("prsdata process exited with error: %v", err)
	}

	return nil
}

func handlePingbackConn(conn net.Conn, expect []byte) error {
	defer conn.Close()
	confirmationBytes, err := ioutil.ReadAll(io.LimitReader(conn, 32))
	if err != nil {
		return err
	}
	if !bytes.Equal(confirmationBytes, expect) {
		return fmt.Errorf("wrong confirmation: %x", confirmationBytes)
	}
	return nil
}

func startPingback(pingback string) error {
	confirmationBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading confirmation bytes from stdin: %v", err)
	}
	conn, err := net.Dial("tcp", pingback)
	if err != nil {
		return fmt.Errorf("dialing confirmation address: %v", err)
	}
	defer conn.Close()
	_, err = conn.Write(confirmationBytes)
	if err != nil {
		return fmt.Errorf("writing confirmation bytes to %s: %v", pingback, err)
	}
	return nil
}
