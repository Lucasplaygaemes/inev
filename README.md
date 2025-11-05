# How it works?
This is a simple code, where you have a "secret file" that you want to share with other people, but in a constantly atteckd web and security word by hackers and bad-intentioned people, you can "encrypt" your file using the inev.
Inev read the file, and parse the hexadecimal code of it, and search for the pattern in other file, then write where it is, but sometimes it can't find, so he writes the hexa down, but to avoid this you can use the strict flag, so if it didn't find, the code stops.

# How to use:

## COMPILE

### With The Makefile
You can compile with the command:

```make```
And clean with:
```make clean```

#### With simple commands
You can compile using these commands:

```gcc -o encoder encoder.c suffix_tree.c -lssl -lcrypto -Wall ```
```gcc -o decoder decoder.c -lssl -lcrypto -Wall```

# Use of the encoder

## Base syntax:
./encoder [--strict] <secret_file> <carrier1> <carrier2> ...

### Example (Normal Mode - recommended):
./encoder my_secret.txt /path/to/carriers/*

### Strict mode example (Fails if do not find 100% matchs)
./encoder --strict my_secret.txt <carrier1> <carrier2> ...

## Use of the decoder:
./decoder -m map.txt -o secret_file.txt <carriers> (or path to the carriers) /path/to/the/carriers/*

## Advanced use of the bash
shopt -s globstar extglob

## Recursive Exemple:
./encoder secret.txt /home/user/docs/**

Exclusion Example:
./encoder secret.txt /home/user/docs/!(*.tmp|cache_dir)
