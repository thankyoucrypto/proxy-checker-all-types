import aiohttp
import asyncio
import time
import os
import requests
from concurrent.futures import ThreadPoolExecutor


# -------------------- CONFIG --------------------

TEST_URL = "https://duckduckgo.com/"  # URL для проверки

MAX_CONCURRENT_CHECKS = 20           # Максимальное количество одновременных проверок прокси

MAX_TIMEOUT = 10                      # Максимальное время ожидания ответа от прокси

PROXY_FILE = 'proxy.txt'              # Файл с прокси

OUTPUT_FOLDER = "proxy_results"       # Папка для хранения результатов

# -------------------- CONFIG --------------------


# Функция для парсинга прокси из строки
def parse_proxy(proxy_str):
    protocol = None
    login = password = ip = port = None

    # Определяем протокол, если он указан
    if proxy_str.startswith('socks5://'):
        protocol = 'socks5'
        proxy_str = proxy_str.replace('socks5://', '')
    elif proxy_str.startswith('http://'):
        protocol = 'http'
        proxy_str = proxy_str.replace('http://', '')

    # Если в строке есть символ "@", разбиваем на две части
    if '@' in proxy_str:
        part1, part2 = proxy_str.split('@', 1)

        # Определение ip:port и login:password
        if part1.count('.') == 3 and part1.count(':') == 1:
            # Если первая часть похожа на ip:port
            ip, port = part1.split(':')
            login, password = part2.split(':', 1)
        elif part2.count('.') == 3 and part2.count(':') == 1:
            # Если вторая часть похожа на ip:port
            ip, port = part2.split(':')
            login, password = part1.split(':', 1)
        else:
            raise ValueError("Unexpected proxy format.")

    else:
        # Обработка форматов без "@"
        parts = proxy_str.split(':')
        if len(parts) == 2:  # Формат ip:port
            ip, port = parts
        elif len(parts) == 4:  # Форматы ip:port:login:pass и login:pass:ip:port
            if parts[0].count('.') == 3 and parts[1].isdigit():  # Формат ip:port:login:pass
                ip, port, login, password = parts
            elif parts[2].count('.') == 3 and parts[3].isdigit():  # Формат login:pass:ip:port
                login, password, ip, port = parts
        else:
            raise ValueError("Unexpected proxy format.")

    # Проверка, что порт является числом
    if not port.isdigit():
        raise ValueError(f"Invalid port value: {port}")

    return {
        'protocol': protocol,
        'ip': ip,
        'port': int(port),
        'login': login,
        'password': password
    }


# Синхронная функция для проверки socks5-прокси с использованием requests
def check_socks5_proxy_sync(proxy, original_proxy_str):
    proxy_url = f"{proxy['ip']}:{proxy['port']}"
    proxies = {
        'http': f'socks5://{proxy["login"]}:{proxy["password"]}@{proxy_url}',
        'https': f'socks5://{proxy["login"]}:{proxy["password"]}@{proxy_url}',
    }

    try:
        start_time = time.time()  # Засекаем время до запроса
        response = requests.get(TEST_URL, proxies=proxies, timeout=MAX_TIMEOUT)
        response_time = time.time() - start_time  # Вычисляем время ответа
        if response.status_code == 200:
            print(
                f"Working proxy: {original_proxy_str} - Protocol: socks5 - Response time: {response_time:.2f} seconds")
            with open(os.path.join(OUTPUT_FOLDER, 'valid_socks5.txt'), 'a') as valid_file:
                valid_file.write(f"{original_proxy_str}\n")
            with open(os.path.join(OUTPUT_FOLDER, 'valid_total.txt'), 'a') as valid_file:
                valid_file.write(f"{original_proxy_str}\n")
            return True
        else:
            print(f"Failed proxy: {original_proxy_str} - Protocol: socks5 - Status code: {response.status_code}")
    except requests.exceptions.ProxyError as e:
        print(f"Proxy authentication failed for socks5 proxy: {original_proxy_str} - Error: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Error with proxy {original_proxy_str} - Protocol: socks5: {e}")

    return False


# Асинхронная обертка для проверки socks5-прокси
async def check_socks5_proxy(semaphore, proxy, original_proxy_str, executor):
    async with semaphore:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(executor, check_socks5_proxy_sync, proxy, original_proxy_str)


# Асинхронная функция для проверки http-прокси
async def check_http_proxy(semaphore, session, proxy, original_proxy_str):
    async with semaphore:
        protocol = proxy['protocol'] or 'http'
        proxy_url = f"http://{proxy['ip']}:{proxy['port']}"
        auth = aiohttp.BasicAuth(proxy['login'], proxy['password']) if proxy['login'] and proxy['password'] else None

        try:
            start_time = time.time()  # Засекаем время до запроса
            async with session.get(TEST_URL, proxy=proxy_url, proxy_auth=auth, timeout=20) as response:
                response_time = time.time() - start_time  # Вычисляем время ответа
                if response.status == 200:
                    print(
                        f"Working proxy: {original_proxy_str} - Protocol: {protocol} - Response time: {response_time:.2f} seconds")
                    with open(os.path.join(OUTPUT_FOLDER, 'valid_http.txt'), 'a') as valid_file:
                        valid_file.write(f"{original_proxy_str}\n")
                    with open(os.path.join(OUTPUT_FOLDER, 'valid_total.txt'), 'a') as valid_file:
                        valid_file.write(f"{original_proxy_str}\n")
                    return True
                elif response.status == 407:
                    print(f"Proxy authentication required for HTTP proxy: {original_proxy_str}")
                else:
                    print(f"Failed proxy: {original_proxy_str} - Protocol: {protocol} - Status code: {response.status}")
        except aiohttp.ClientHttpProxyError as e:
            print(f"HTTP Proxy error: {e}")
        except Exception as e:
            print(f"Error with proxy {original_proxy_str} - Protocol: {protocol}: {e}")

        return False


# Функция для проверки прокси с переключением между http и socks5, если протокол не указан
async def check_proxy(semaphore, session, proxy, original_proxy_str, executor, counts, invalid_proxies):
    is_valid = False
    if proxy['protocol'] is None:
        # Попробуем сначала http
        if await check_http_proxy(semaphore, session, proxy, original_proxy_str):
            counts['http'] += 1
            is_valid = True
        else:
            # Если http не сработал, попробуем socks5
            if await check_socks5_proxy(semaphore, proxy, original_proxy_str, executor):
                counts['socks5'] += 1
                is_valid = True
    elif proxy['protocol'] == 'socks5':
        if await check_socks5_proxy(semaphore, proxy, original_proxy_str, executor):
            counts['socks5'] += 1
            is_valid = True
    else:
        if await check_http_proxy(semaphore, session, proxy, original_proxy_str):
            counts['http'] += 1
            is_valid = True

    if not is_valid:
        invalid_proxies[0] += 1  # Используем список, чтобы сохранять изменения в счётчике


# Основная функция для проверки всех прокси
async def main():
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
        all_check_tasks = []
        executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CHECKS)

        # Создаем папку для хранения результатов
        if not os.path.exists(OUTPUT_FOLDER):
            os.makedirs(OUTPUT_FOLDER)

        # Очищаем или создаем файлы для записи валидных прокси
        open(os.path.join(OUTPUT_FOLDER, 'valid_http.txt'), 'w').close()
        open(os.path.join(OUTPUT_FOLDER, 'valid_socks5.txt'), 'w').close()
        open(os.path.join(OUTPUT_FOLDER, 'valid_total.txt'), 'w').close()

        counts = {'http': 0, 'socks5': 0}
        total_proxies = 0
        invalid_proxies = [0]  # Используем список для возможности изменения внутри async функций

        with open(PROXY_FILE, 'r') as f:
            proxies = f.readlines()

        # Парсим и проверяем каждый прокси
        for proxy_str in proxies:
            total_proxies += 1
            try:
                proxy = parse_proxy(proxy_str.strip())
                check_task = check_proxy(semaphore, session, proxy, proxy_str.strip(), executor, counts,
                                         invalid_proxies)
                all_check_tasks.append(check_task)
            except ValueError as e:
                print(f"Skipping invalid proxy format: {proxy_str.strip()} - Error: {e}")
                invalid_proxies[0] += 1
                continue

        # Выполняем проверку всех прокси асинхронно с ограничением на количество одновременных задач
        await asyncio.gather(*all_check_tasks)

        # Вывод итогов
        total_valid_proxies = counts['http'] + counts['socks5']
        print(f"\n----- Summary -----")
        print(f"{'Total checked:':<14} {total_proxies}")
        print(f"{'Valid/Invalid:':<14} {total_valid_proxies}/{invalid_proxies[0]}\n")
        print(f"{'HTTP valid:':<14} {counts['http']}")
        print(f"{'SOCKS5 valid:':<14} {counts['socks5']}")


if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(main())
    print(f"___________________\nFinished in {time.time() - start_time} seconds.")
