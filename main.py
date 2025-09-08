#!/usr/bin/env python3
"""
D-Link Device Scanner
Продвинутый сканер D-Link устройств с улучшенной структурой файлов

Автор: Security Research
Версия: 3.0 Enhanced
"""

import argparse
import requests
import requests.adapters
import signal
import sys
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ipaddress
import socket
import queue
import os
from datetime import datetime
import re

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FileManager:
    """Управление файлами и папками результатов"""
    def __init__(self):
        self.session_folder = self.setup_results_folder()
        self.device_types = {
            'routers': [],
            'cameras': [],
            'switches': [],
            'access_points': [],
            'unknown': []
        }
        self.all_devices = []
        self.lock = threading.Lock()

    def setup_results_folder(self):
        """Создает и очищает папку results"""
        folder_name = "results"
        
        # Очистка существующей папки
        if os.path.exists(folder_name):
            import shutil
            shutil.rmtree(folder_name)
        
        # Создание новой папки
        os.makedirs(folder_name, exist_ok=True)
        return folder_name

    def classify_device(self, response_text, headers):
        """Классифицирует устройство по типу"""
        text_lower = response_text.lower()
        headers_lower = ' '.join([f"{k}: {v}" for k, v in headers.items()]).lower()
        combined = text_lower + ' ' + headers_lower

        # Роутеры (DIR, DWR, DSL, DVG)
        if any(keyword in combined for keyword in ['dir-', 'dwr-', 'dsl-', 'dvg-', 'router', 'gateway', 'modem', 'adsl']):
            return 'routers'
        # Камеры (DCS)
        elif any(keyword in combined for keyword in ['dcs-', 'camera', 'webcam', 'ip cam', 'surveillance']):
            return 'cameras'
        # Коммутаторы (DGS, DES)
        elif any(keyword in combined for keyword in ['dgs-', 'des-', 'switch', 'ethernet', 'managed switch']):
            return 'switches'
        # Точки доступа (DAP, DWA)
        elif any(keyword in combined for keyword in ['dap-', 'dwa-', 'access point', 'wireless', 'wifi']):
            return 'access_points'
        else:
            return 'unknown'

    def save_device(self, host, device_type, device_info=None):
        """Сохраняет устройство в соответствующий файл"""
        with self.lock:
            # Добавляем в общий список
            self.all_devices.append({'host': host, 'type': device_type, 'info': device_info})
            self.device_types[device_type].append(host)

            # Сохраняем в файлы
            self._write_to_files(host, device_type, device_info)

    def _write_to_files(self, host, device_type, device_info):
        """Записывает в файлы"""
        # Общий файл со всеми IP
        all_file = os.path.join(self.session_folder, "all_dlink_devices.txt")
        with open(all_file, 'a') as f:
            f.write(f"{host}\n")

        # Файл по типу устройства
        type_file = os.path.join(self.session_folder, f"{device_type}.txt")
        with open(type_file, 'a') as f:
            f.write(f"{host}\n")

        # Детальный файл с информацией
        detail_file = os.path.join(self.session_folder, f"{device_type}_detailed.txt")
        with open(detail_file, 'a') as f:
            info_str = device_info if device_info else "Unknown device info"
            f.write(f"{host} | {info_str}\n")

    def get_summary(self):
        """Возвращает сводку результатов"""
        with self.lock:
            return {
                'total': len(self.all_devices),
                'by_type': {k: len(v) for k, v in self.device_types.items()},
                'session_folder': self.session_folder
            }

class Statistics:
    """Thread-safe statistics tracker"""
    def __init__(self):
        self.processed_count = 0
        self.vulnerable_found = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.dlink_hosts = []

    def increment_processed(self):
        with self.lock:
            self.processed_count += 1

    def increment_vulnerable(self, host):
        with self.lock:
            self.vulnerable_found += 1
            self.dlink_hosts.append(host)

    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.processed_count / elapsed if elapsed > 0 else 0
            return {
                'processed_count': self.processed_count,
                'vulnerable': self.vulnerable_found,
                'rate': rate,
                'elapsed': elapsed,
                'hosts': self.dlink_hosts.copy()
            }

class DLinkScanner:
    """Продвинутый сканер D-Link устройств с классификацией"""

    def __init__(self, stats, file_manager, timeout=3):
        self.stats = stats
        self.file_manager = file_manager
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        # Оптимизация для большого количества соединений
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=50,
            pool_maxsize=50,
            max_retries=0
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Connection': 'close'
        })

    def detect_dlink(self, host):
        """Улучшенное обнаружение D-Link устройств с деталями"""
        try:
            # Расширенные методы обнаружения
            checks = [
                # HNAP check - главный метод
                {
                    'url': f"http://{host}/HNAP1/",
                    'method': 'GET',
                    'headers': {'SOAPAction': '"http://purenetworks.com/HNAP1/GetDeviceSettings"'},
                    'indicators': ['HNAP', 'D-Link', 'purenetworks.com', 'DeviceType'],
                    'priority': 1
                },
                # Быстрая проверка главной страницы
                {
                    'url': f"http://{host}/",
                    'method': 'GET',
                    'headers': {},
                    'indicators': ['D-Link', 'DIR-', 'DAP-', 'DCS-', 'DWR-', 'DGS-', 'DES-', 'DHP-', 'DWA-', 'DPH-', 'DSL-', 'DVG-'],
                    'priority': 2
                },
                # Проверка страницы входа
                {
                    'url': f"http://{host}/login.php",
                    'method': 'GET',
                    'headers': {},
                    'indicators': ['D-Link', 'Router', 'Access Point'],
                    'priority': 3
                },
                # Дополнительные проверки
                {
                    'url': f"http://{host}/info.html",
                    'method': 'GET',
                    'headers': {},
                    'indicators': ['D-Link', 'Model'],
                    'priority': 4
                }
            ]

            # Сортируем по приоритету
            checks.sort(key=lambda x: x['priority'])
            
            for check in checks:
                try:
                    response = self.session.get(check['url'], headers=check['headers'], timeout=self.timeout)
                    
                    if response.status_code == 200:
                        response_text = response.text
                        headers_dict = dict(response.headers)
                        combined_text = response_text.lower() + ' ' + ' '.join([f"{k}: {v}" for k, v in headers_dict.items()]).lower()

                        for indicator in check['indicators']:
                            if indicator.lower() in combined_text:
                                # Извлекаем информацию об устройстве
                                device_info = self.extract_device_info(response_text, headers_dict)
                                return True, device_info, response_text, headers_dict

                except Exception:
                    continue

        except Exception:
            pass

        return False, None, None, None

    def extract_device_info(self, response_text, headers):
        """Извлекает информацию об устройстве"""
        info = {}
        text_lower = response_text.lower()
        
        # Ищем модель устройства - все популярные линейки D-Link
        model_patterns = [
            # Роутеры DIR (самые популярные)
            r'(DIR-\d+[A-Z]*)',  # DIR-615, DIR-645, DIR-300, DIR-825, DIR-878, DIR-882, DIR-1260, DIR-3040
            # Точки доступа DAP
            r'(DAP-\d+[A-Z]*)',  # DAP-1360, DAP-1522, DAP-2230, DAP-2660
            # IP камеры DCS
            r'(DCS-\d+[A-Z]*)',  # DCS-930L, DCS-942L, DCS-5222L, DCS-8000LH
            # Модемы/роутеры DWR
            r'(DWR-\d+[A-Z]*)',  # DWR-921, DWR-953, DWR-956, DWR-2101
            # Коммутаторы DGS
            r'(DGS-\d+[A-Z]*)',  # DGS-1008, DGS-1016, DGS-1210, DGS-3120
            # Коммутаторы DES (старые модели)
            r'(DES-\d+[A-Z]*)',  # DES-1008, DES-1016, DES-3010
            # Powerline адаптеры DHP
            r'(DHP-\d+[A-Z]*)',  # DHP-600AV, DHP-701AV
            # Wi-Fi адаптеры DWA
            r'(DWA-\d+[A-Z]*)',  # DWA-131, DWA-171, DWA-192
            # VoIP телефоны DPH
            r'(DPH-\d+[A-Z]*)',  # DPH-120S, DPH-150S
            # ADSL модемы DSL
            r'(DSL-\d+[A-Z]*)',  # DSL-2640U, DSL-2750U
            # VoIP шлюзы DVG
            r'(DVG-\d+[A-Z]*)',  # DVG-N5402SP
            # Общие паттерны
            r'model["\s:]+([A-Z]+-\d+[A-Z]*)',
            r'product["\s:]+([A-Z]+-\d+[A-Z]*)',
            r'device["\s:]+([A-Z]+-\d+[A-Z]*)'
        ]
        
        for pattern in model_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                info['model'] = match.group(1)
                break
        
        # Ищем версию прошивки
        fw_patterns = [
            r'firmware["\s:]+([0-9.]+)',
            r'version["\s:]+([0-9.]+)',
            r'ver["\s:]+([0-9.]+)'
        ]
        
        for pattern in fw_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                info['firmware'] = match.group(1)
                break
        
        # Server header
        if 'Server' in headers:
            info['server'] = headers['Server']
            
        return info

    def scan_single_host(self, host):
        """Улучшенное сканирование с сохранением в файлы"""
        self.stats.increment_processed()

        # Очистка формата хоста
        if host.startswith(('http://', 'https://')):
            host = urlparse(host).netloc

        # Извлечение IP без порта для IPv4
        if ':' in host and not host.count(':') > 1:
            host = host.split(':')[0]

        try:
            # Обнаружение D-Link устройства
            is_dlink, device_info, response_text, headers = self.detect_dlink(host)
            if is_dlink:
                self.stats.increment_vulnerable(host)
                
                # Классификация устройства
                device_type = self.file_manager.classify_device(response_text or "", headers or {})
                
                # Сохранение в файлы
                self.file_manager.save_device(host, device_type, device_info)
                
                return {'host': host, 'type': device_type, 'info': device_info}

        except Exception:
            pass

        return None

def is_valid_target(target):
    """Quick validation for single target"""
    # Clean target
    clean_target = target
    if target.startswith(('http://', 'https://')):
        clean_target = urlparse(target).netloc

    if ':' in clean_target and not clean_target.count(':') > 1:
        clean_target = clean_target.split(':')[0]

    # Validate IP
    try:
        ipaddress.ip_address(clean_target)
        return True
    except ValueError:
        try:
            socket.gethostbyname(clean_target)
            return True
        except socket.gaierror:
            return False

def validate_and_filter_targets(targets):
    """Validate and filter target list, removing invalid IPs and duplicates"""
    valid_targets = []

    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)

    for target in unique_targets:
        # Clean target (remove protocol, port if present)
        clean_target = target
        if target.startswith(('http://', 'https://')):
            clean_target = urlparse(target).netloc

        # Extract IP without port for IPv4
        if ':' in clean_target and not clean_target.count(':') > 1:
            clean_target = clean_target.split(':')[0]

        # Validate IP address
        try:
            ipaddress.ip_address(clean_target)
            valid_targets.append(clean_target)
        except ValueError:
            # Try to resolve hostname
            try:
                socket.gethostbyname(clean_target)
                valid_targets.append(clean_target)
            except socket.gaierror:
                continue

    return valid_targets

def main():
    parser = argparse.ArgumentParser(description='Продвинутый сканер D-Link устройств v3.0')
    parser.add_argument('-t', '--threads', type=int, default=300, 
                       help='Количество потоков (по умолчанию: 300)')
    parser.add_argument('-f', '--file', 
                       help='Файл с целевыми IP адресами')
    parser.add_argument('--timeout', type=int, default=3, 
                       help='Таймаут запроса в секундах (по умолчанию: 3)')
    parser.add_argument('--max-threads', type=int, default=500,
                       help='Максимальное количество потоков (по умолчанию: 500)')

    args = parser.parse_args()

    # Ограничение количества потоков для стабильности
    if args.threads > args.max_threads:
        print(f"[!] Ограничение потоков до {args.max_threads} для стабильности")
        args.threads = args.max_threads

    # Обработка сигналов
    def signal_handler(sig, frame):
        print('\n[!] Прервано пользователем')
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Инициализация компонентов
    stats = Statistics()
    file_manager = FileManager()
    scanner = DLinkScanner(stats, file_manager, timeout=args.timeout)

    # Печать информации о сессии
    print(f"[+] Сканер D-Link устройств v3.0")
    print(f"[+] Папка результатов: {file_manager.session_folder}/ (очищена)")
    print(f"[+] Потоков: {args.threads}, Таймаут: {args.timeout}s")
    print(f"[+] Поддерживаемые модели: DIR-, DAP-, DCS-, DWR-, DGS-, DES-, DHP-, DWA-, DPH-, DSL-, DVG-")

    # Get targets
    targets = []

    if args.file:
        # File mode
        try:
            with open(args.file, 'r') as f:
                raw_targets = [line.strip() for line in f if line.strip()]
                targets = validate_and_filter_targets(raw_targets)
        except FileNotFoundError:
            print(f"[!] File '{args.file}' not found")
            sys.exit(1)

        if not targets:
            print("[!] No valid targets found")
            sys.exit(1)

        print(f"[+] Starting D-Link scanner with {len(targets)} targets")
        print(f"[+] Using {args.threads} threads, timeout: {args.timeout}s")

        # Начинаем сканирование
        start_time = time.time()
        dlink_results = []

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Отправляем все задачи сканирования
            futures = [executor.submit(scanner.scan_single_host, target.strip()) 
                      for target in targets]

            # Обрабатываем результаты с отображением прогресса
            last_update = time.time()
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:  # Если найдено D-Link устройство
                        dlink_results.append(result)

                except Exception:
                    pass

                # Показываем прогресс каждую секунду
                current_time = time.time()
                if current_time - last_update >= 1.0:
                    last_update = current_time
                    data = stats.get_stats()
                    print(f"\r📊 Прогресс: {data['processed_count']} сканировано | {data['vulnerable']} найдено | Скорость: {data['rate']:.1f}/сек", end="", flush=True)

        # Финальные результаты
        final_stats = stats.get_stats()
        summary = file_manager.get_summary()
        
        print(f"\n[+] Сканирование завершено!")
        print(f"[+] Всего сканировано: {final_stats['processed_count']}")
        print(f"[+] D-Link устройств найдено: {final_stats['vulnerable']}")
        print(f"[+] Время сканирования: {final_stats['elapsed']:.1f} секунд")
        print(f"[+] Результаты сохранены в: {summary['session_folder']}/")
        
        # Показываем статистику по типам
        print(f"\n[+] Статистика по типам устройств:")
        for device_type, count in summary['by_type'].items():
            if count > 0:
                print(f"  - {device_type}: {count}")
        
        print(f"\n[+] Созданные файлы:")
        print(f"  - all_dlink_devices.txt - все найденные IP")
        for device_type, count in summary['by_type'].items():
            if count > 0:
                print(f"  - {device_type}.txt - IP {device_type}")
                print(f"  - {device_type}_detailed.txt - детальная информация")

        if dlink_results:
            print(f"\n[+] Примеры найденных устройств:")
            for result in dlink_results[:5]:  # Показываем первые 5
                host = result['host']
                device_type = result['type']
                info = result.get('info', {})
                model = info.get('model', 'Unknown')
                print(f"  - {host} ({device_type}) - {model}")
            if len(dlink_results) > 5:
                print(f"  ... и еще {len(dlink_results) - 5}")
    else:
        # Режим stdin - потоковое сканирование в реальном времени
        print("[+] D-Link сканер потокового режима - чтение из stdin")
        print("[+] Нажмите Ctrl+C для остановки")

        # Потоковое сканирование из stdin
        dlink_results = []
        start_time = time.time()
        last_update = time.time()

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            active_futures = []

            try:
                for line in sys.stdin:
                    target = line.strip()
                    if target and is_valid_target(target):
                        # Отправляем задачу сканирования
                        future = executor.submit(scanner.scan_single_host, target)
                        active_futures.append(future)

                        # Очищаем завершенные futures
                        completed = [f for f in active_futures if f.done()]
                        for f in completed:
                            try:
                                result = f.result()
                                if result:  # Найдено D-Link устройство
                                    dlink_results.append(result)
                            except:
                                pass

                        # Оставляем только активные futures
                        active_futures = [f for f in active_futures if not f.done()]

                        # Показываем прогресс каждую секунду
                        current_time = time.time()
                        if current_time - last_update >= 1.0:
                            last_update = current_time
                            data = stats.get_stats()
                            print(f"\r📊 Прогресс: {data['processed_count']} сканировано | {data['vulnerable']} найдено | Скорость: {data['rate']:.1f}/сек | Активных: {len(active_futures)}", end="", flush=True)

            except KeyboardInterrupt:
                print("\n[!] Остановка сканера...")

            # Ждем завершения оставшихся задач
            for f in active_futures:
                try:
                    result = f.result(timeout=1)
                    if result:
                        dlink_results.append(result)
                except:
                    pass

        # Финальная сводка для режима stdin
        elapsed_total = time.time() - start_time
        summary = file_manager.get_summary()
        
        print(f"\n[+] Потоковое сканирование завершено!")
        print(f"[+] Всего сканировано: {stats.get_stats()['processed_count']}")
        print(f"[+] D-Link устройств найдено: {len(dlink_results)}")
        print(f"[+] Время сканирования: {elapsed_total:.1f}s")
        print(f"[+] Результаты сохранены в: {summary['session_folder']}/")

        # Показываем статистику по типам
        print(f"\n[+] Статистика по типам устройств:")
        for device_type, count in summary['by_type'].items():
            if count > 0:
                print(f"  - {device_type}: {count}")

        if dlink_results:
            print(f"\n[+] Примеры найденных устройств:")
            for result in dlink_results[:5]:  # Показываем первые 5
                host = result['host']
                device_type = result['type']
                info = result.get('info', {})
                model = info.get('model', 'Unknown')
                print(f"  - {host} ({device_type}) - {model}")
            if len(dlink_results) > 5:
                print(f"  ... и еще {len(dlink_results) - 5}")

if __name__ == "__main__":
    main()
