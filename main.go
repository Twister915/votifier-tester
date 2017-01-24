package main

import (
	"net"
	"flag"
	"fmt"
	"os"
	"strconv"
	"encoding/base64"
	"io/ioutil"
	"crypto/x509"
	"crypto/rsa"
	"io"
	"bytes"
	"crypto/rand"
	"time"
	"strings"
)

func main() {
	pubkey := flag.String("key", "public.key", "The public key file location")
	target := flag.String("target", "", "The target (host:rawPort) to send the votifier thing to")
	username := flag.String("username", "Player", "The username of the player who sent the vote")
	site := flag.String("site", "test.twister915.me", "The name of the website sending the vote")
	voterIp := flag.String("address", "127.0.0.1", "The IP of the person making the vote")
	rawCount := flag.String("count", "1", "The number of votes you want to send.")
	rawDelay := flag.String("delay", "1s", "The amount of time between votes in succession.")

	flag.Parse()
	if len(*target) == 0 {
		fmt.Fprint(os.Stderr, "You need to specify your target. Use the following help:\n")
		flag.Usage()
	}

	count, err := strconv.ParseInt(*rawCount, 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid vote count \"%s\"! error: %s\n", *rawCount, err.Error())
		return
	}

	delay, err := time.ParseDuration(*rawDelay)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid delay \"%s\"! error: %s\n", *rawDelay, err.Error())
		return
	}

	var rsaKey *rsa.PublicKey
	{
		data, err := ioutil.ReadFile(*pubkey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Your public key could not be read at %s! Error: %s\n", *pubkey, err.Error())
			return
		}

		pubKeyBytes, err := base64.StdEncoding.DecodeString(string(data))

		if err != nil {
			fmt.Fprintf(os.Stderr, "Your public key could not be decoded! I'm expecting the public key directly from your votifier plugins folder (base64). The error was: %s\n", err.Error())
			return
		}

		k, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not parse your key as PKIX x509 (encoding error). Error: %s\n", err.Error())
		}
		rsaKey = k.(*rsa.PublicKey)
	}

	host, rawPort, err := net.SplitHostPort(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not parse the target provided! %s\n", err.Error())
		return
	}

	if len(*username) < 1 || len(*username) > 16 {
		fmt.Fprintf(os.Stderr, "The username %s was not valid!\n", *username)
		return
	}

	port, err := strconv.ParseInt(rawPort, 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port %s: %s\n", rawPort, err.Error())
		return
	}

	sendVote := func() {
		conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP(host), Port: int(port)})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not establish a connection. Error: %s\n", err.Error())
			return
		}
		defer conn.Close()
		ver, err := ReadVersion(conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to %s. Error: %s\n", *target, err.Error())
			return
		}
		fmt.Printf("Connected to votifier at %s (version %s)\n", *target, ver)

		err = VotifierMessage{*site, *username, *voterIp, time.Now().Format(time.UnixDate)}.Write(rsaKey, conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sending packet... %s\n", err.Error())
			panic(err)
		}
		fmt.Printf("Sent vote to %s!\n", *target)
	}


	for i := 0; i < int(count); i++ {
		if count > 1 {
			fmt.Printf("sending vote #%d...\n\n", i + 1)
		}
		sendVote()
		fmt.Print("done\n")
		if i != int(count - 1) {
			<-time.After(delay)
		}
	}
	fmt.Print("\n")
	if count > 1 {
		fmt.Print("sent all votes!\n")
	}
}

func ReadVersion(reader io.Reader) (version string, err error) {
	buf := make([]byte, 16)
	var read bytes.Buffer
reader:
	for {
		var n int
		n, err = reader.Read(buf)
		if err != nil {
			return
		}

		_, err = read.Write(buf[0:n])
		if err != nil {
			return
		}
		chars := []rune(string(buf))

		for i := 0; i < n; i++ {
			c := chars[i]
			if c == '\n' {
				break reader
			}
		}
	}
	sent := read.String()
	values := strings.Split(sent, " ")
	if len(values) < 2 {
		err = fmt.Errorf("invalid value %s", sent)
		return
	}
	version = strings.Join(values[1:], " ")
	version = strings.TrimSpace(version)
	return
}

type VotifierMessage struct {
	ServiceName, Username, Address, TimeStamp string
}

const desiredSize = 256 - 11 //max size of the block is 256 less 11 bytes as per docs on rsa.EncryptPKCS1v15

func (msg VotifierMessage) Write(key *rsa.PublicKey, writer io.Writer) (err error) {
	var buf bytes.Buffer
	buf.Grow(desiredSize)
	writePart := func(part string) error {
		if len(part) == 0 {
			return fmt.Errorf("invalid write component; is blank")
		}
		_, err := buf.WriteString(part)
		if err != nil {
			return err
		}
		_, err = buf.WriteRune('\n')
		if err != nil {
			return err
		}
		return nil
	}

	err = writePart("VOTE")
	if err != nil {
		return
	}
	err = writePart(msg.ServiceName)
	if err != nil {
		return
	}
	err = writePart(msg.Username)
	if err != nil {
		return
	}
	err = writePart(msg.Address)
	if err != nil {
		return
	}
	err = writePart(msg.TimeStamp)
	if err != nil {
		return
	}

	for buf.Len() < desiredSize {
		err = buf.WriteByte(0)
		if err != nil {
			return
		}
	}

	encryptedMessage, err := rsa.EncryptPKCS1v15(rand.Reader, key, buf.Bytes())
	if err != nil {
		return
	}
	_, err = writer.Write(encryptedMessage)
	return
}
