# 🔥 Ультимативный Прокси Чекер — Поддержка Всех Форматов  
# 🌍 Ultimate Proxy Checker — Supports All Formats

![Logo](logo.jpg)

## 🛠️ О проекте / About the Project

### 🇷🇺 На русском
Этот мощный инструмент проверяет работоспособность прокси-серверов, поддерживающих различные форматы. Поддерживаются как HTTP, так и SOCKS5 прокси. Просто укажите прокси в любом формате, и программа автоматически определит IP, порт, логин и пароль.

### 🇬🇧 In English
This powerful tool checks the functionality of proxy servers supporting various formats. It supports both HTTP and SOCKS5 proxies. Simply specify the proxies in any format, and the program will automatically determine the IP, port, login, and password.

## 📦 Модули / Modules

- **aiohttp**: Асинхронная работа с HTTP-запросами / Asynchronous HTTP requests.
- **requests**: Асинхронная проверка SOCKS5-прокси / Asynchronous checking SOCKS5 proxies.

## 🚀 Установка и запуск / Installation and Setup

### 🇷🇺 На русском
1. Убедитесь, что у вас установлен **Python 3.6** или выше.
2. Скачайте проект и установите зависимости:

   pip install -r requirements.txt

3. Добавьте свои прокси в файл `proxy.txt`.
4. Запустите скрипт:

   python main.py

### 🇬🇧 In English
1. Ensure you have **Python 3.6** or higher installed.
2. Download the project and install the dependencies:

   pip install -r requirements.txt

3. Add your proxies to the `proxy.txt` file.
4. Run the script:

   python main.py

## 📊 Результаты / Results

### 🇷🇺 На русском
Результаты работы скрипта будут сохранены в папке `proxy_results`:

- `valid_http.txt`: Рабочие HTTP прокси.
- `valid_socks5.txt`: Рабочие SOCKS5 прокси.
- `valid_total.txt`: Все рабочие прокси.

### 🇬🇧 In English
The results will be saved in the `proxy_results` folder:

- `valid_http.txt`: Working HTTP proxies.
- `valid_socks5.txt`: Working SOCKS5 proxies.
- `valid_total.txt`: All working proxies.

## 📝 Примечания / Notes

### 🇷🇺 На русском
Для корректной работы отключите **VPN**, если он активен.

### 🇬🇧 In English
For correct functionality, disable **VPN** if it's enabled.

## 📂 Поддерживаемые форматы / Supported Formats

### 🇷🇺 На русском
Укажите свои прокси в `proxy.txt` в одном из следующих форматов:

### 🇬🇧 In English
Specify your proxies in the `proxy.txt` file in any of the following formats:

- ip:port
- ip:port:login:pass
- login:pass:ip:port
- ip:port@login:pass
- login:pass@ip:port
- http://ip:port:login:pass
- http://login:pass:ip:port
- http://login:pass@ip:port
- http://ip:port@login:pass
- socks5://ip:port:login:pass
- socks5://login:pass:ip:port
- socks5://ip:port@login:pass
- socks5://login:pass@ip:port

## 💬 Контакты / Contacts

### 🇷🇺 На русском
Есть вопросы или предложения? Напишите мне в [Telegram](https://t.me/vPoiskahGema) 📲.

### 🇬🇧 In English
Have questions or suggestions? Contact me on [Telegram](https://t.me/vPoiskahGema) 📲.

---

Спасибо за использование Ультимативного Прокси Чекера! 🚀  
Thank you for using the Ultimate Proxy Checker! 🚀
