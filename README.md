# weggli-patterns
[![](https://img.shields.io/github/stars/0xdea/weggli-patterns.svg?color=yellow)](https://github.com/0xdea/weggli-patterns)
[![](https://img.shields.io/github/forks/0xdea/weggli-patterns.svg?color=green)](https://github.com/0xdea/weggli-patterns)
[![](https://img.shields.io/github/watchers/0xdea/weggli-patterns.svg?color=red)](https://github.com/0xdea/weggli-patterns)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)

> "No one gives a s*** about the old scene people anymore I’m sure,  
> bunch of old a** people grepping for the last of the memcpy." 
> 
> -- Bas Alberts

A collection of my weggli patterns to facilitate vulnerability research.

See also:  
https://github.com/weggli-rs/weggli  
https://twitter.com/richinseattle/status/1729654184633327720  

## buffer overflows

### lack of explicit NUL-termination after strncpy() and stpncpy()
```
$ weggli --cpp '{strncpy($buf,_); not: $buf[_]=_;}' . -e c
$ weggli --cpp '{stpncpy($buf,_); not: $buf[_]=_;}' . -e c
```

## integer overflows

## format strings

## memory management

## command injection

## race conditions

## privilege management

### unchecked return code of setuid() and seteuid()
```
$ weggli --cpp '{strict: setuid(_);}' . -e c
$ weggli --cpp '{strict: seteuid(_);}' . -e c
```

## miscellaneous
