# pcap-analyzer

### Разбор PCAP-файла

Для каждого файла собирает статистику:

* Общее количество пакетов.
* Суммарная длина пакетов.
* Распределение длин пакетов в байтах:
  + <=64
  + 65 - 255
  + 256 - 511
  + 512 - 1023
  + 1024 - 1518
  + \> 1519

* Распределение по протоколам:

  + IPv4
  + non-IPv4
  + TCP
  + UDP
  + ICMP
  + other L4

* Количество уникальных значений по полям:

  + src_mac
  + dst_mac
  + src_ip
  + dst_ip
  + src_port
  + dst_port

* Для TCP-пакетов pаспределение по флагам SYN, ACK, FIN, RST:

  + SYN
  + SYN + ACK
  + ACK
  + FIN + ACK
  + RST
  + RST + ACK
  + other

* Количество пакетов с корректной и некорректной чексуммой L3 и L4 заголовков.

#### Требования:

* Программа должна принимать путь к каталогу с pcap-файлами из приложенного архива
  и выводить по каждому файлу статистику в консоль в текстовом виде с указанием
  названия файла.
* Код писать на C++11 или выше.
* Для чтения pcap использовать libpcap, разбор пакетов и проверки чексум делать самому.

### Сборка
```
git submodule update --init --recursive

```
Создаем папку build и в ней собираем:
```
cmake ..
cmake --build .
```

### Запуск
 ```
 pcap_analyzer -i путь до входного файла pcap.
 ```