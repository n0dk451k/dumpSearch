# dumpSearch
поиск сигнатур в бинарных дампах 
```
Использование:
  ./search <file> [options]

Поиск:
  --utf8 <string>
  --utf16le <string>
  --utf16be <string>
  --hex <hexstring>

Вывод:
  --xxd "<args>"
  --strings "<args>"
  --strings-len <N>
  --offset-add <N>
  --progress <seconds>
  --help
```

```
./search ./dump.bin --utf8 "substr"
./search ./dump.bin --utf16l "substr" --strings-len 1024 --strings-len 100 --strings "-e S"
./search ./dump.bin --utf16b "substr" --offset-add -32 --xxd "-c 32 -l 256"
./search ./pagefile.sys --hex "deadbeef" --xxd "-c 32 -l 64"
./search ./dump.bin --utf8 "substr" --strings-len 1024 --offset-add -32 --strings-len 100 --strings "-e S" --xxd "-c 32 -l 256"    
```
