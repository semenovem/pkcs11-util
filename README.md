# Утилиты PKCS11

## Общая информация

Утилиты включают в себя:

1 Библиотеку для работы с HSM по протоколу PKCS11 языка программирования Go  
2 Инструмент коммандной строки hsmc для работы с HSM (использует библиотеку)  

## Сборка инструмента командной строки

### Локальная

```
$ make PKCS11_HOST_LIB={путь к библиотеке pkcs11} build
```

### В контейнере Docker

```
$ make PKCS11_HOST_LIB={путь к библиотеке pkcs11} docker
$ make DEST_DIR={место расположения, куда копировать бинарник} export
```


#####
Пример значений `PKCS11_HOST_LIB`
```
softhsm
PKCS11_HOST_LIB=/usr/lib/softhsm/libsofthsm2.so

тестовое окружение в iNET
PKCS11_HOST_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so
```
