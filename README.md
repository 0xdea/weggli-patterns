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
https://dustri.org/b/playing-with-weggli.html  
https://github.com/plowsec/weggli-patterns  
https://github.com/synacktiv/Weggli_rules_SSTIC2023  
https://twitter.com/richinseattle/status/1729654184633327720  

## buffer overflows

### call to insecure API functions
```
weggli -R 'func=^get' '{$func(_);}' .
weggli -R 'func=^st(r|p)(cpy|cat)' '{$func(_);}' .
weggli -R 'func=^wc(s|p)(cpy|cat)' '{$func(_);}' .
weggli -R 'func=sprintf$' '{$func(_);}' .
weggli -R 'func=scanf$' '{$func(_);}' .
```

### incorrect use of strncat
```
weggli '{strncat(_,_,sizeof(_));}' .
weggli '{strncat(_,_,strlen(_));}' .
weggli '{strncat($dst,$src,sizeof($dst)-strlen($dst));}' .

# this won't work due to current limitations in the query language
# weggli '{_ $buf[$len]; strncat($buf,_,$len);}'
# https://github.com/weggli-rs/weggli/issues/59
```

### destination buffer access using size of source buffer

TBD

### lack of explicit NUL-termination after strncpy(), etc.
```
weggli '{strncpy($buf,_); not: $buf[_]=_;}' .
weggli '{stpncpy($buf,_); not: $buf[_]=_;}' .

# some variants
# read(), readlink(), fread(), memcpy(), etc.
```

### potentially unsafe use of the return value of snprintf(), etc.
```
weggli '{$ret=snprintf($buf,_,_);}'
weggli '{$ret=snprintf($buf,_,_); $buf[$ret]=_;}'

# some variants
weggli '{$ret=vsnprintf($buf,_,_);}'
weggli '{$ret=strlcpy($buf,_,_);}'
weggli '{$ret=strlcat($buf,_,_);}'
weggli '{$ret=wcslcpy($buf,_,_);}'
weggli '{$ret=wcslcat($buf,_,_);}'
```

### direct write into buffer allocated on the stack
```
weggli '{_ $buf[]; strncpy($buf,_,_);}' .
weggli -R 'func=^mem' '{_ $buf[_]; $func($buf,_,_);}' .

# some variants
# strcpy, strncpy, stpcpy, stpncpy, strlcpy
# wcscpy, wcsncpy, wcpcpy, wcpncpy, wcslcpy
# strcat, strncat, strlcat, wcscat, wcsncat, wcslcat
# memcpy, memccpy, memmove, memset, wmemcpy, wmemmove, wmemset
# sprintf, vsprintf, snprintf, vsnprintf
# gets, fgets, getwd, getcwd, fread
# bcopy
# read, pread, recv, recvfrom
# simple assignment
```

## integer overflows

### signed or short sizes, lengths, offsets, counts
```
weggli '{short _;}' .
weggli '{int _;}' .

# some variants
# short int
# unsigned short
# unsigned short int
# int
```

### casting the return value of strlen(), wcslen() to short
```
weggli '{short $len; $len=strlen(_);}' .
weggli '{short $len; $len=wcslen(_);}' .

# some variants
# short int
# unsigned short
# unsigned short int
```

## format strings

### find printf(), scanf(), syslog() family functions
```
weggli -R 'func=printf$' '{$func(_);}' .
weggli -R 'func=scanf$' '{$func(_);}' .
weggli -R 'func=syslog$' '{$func(_);}' .

# some variants
# printk
# warn, vwarn, warnx, vwarnx
# err, verr, errx, verrx, warnc, vwarnc
# errc, verrc
```

## memory management

### use of uninitialized variables
```
weggli '{_* $p; not: $p =_; not: $func1(&$p); $func2($p);}' .
weggli '{_ $p[]; not: $p =_; not: $func1(&$p); $func2($p);}' .
```

## command injection

TBD

## race conditions

TBD

## privilege management

### unchecked return code of setuid() and seteuid()
```
weggli '{strict: setuid(_);}' .
weggli '{strict: seteuid(_);}' .
```

## miscellaneous

### command-line argument or environment variable access
```
weggli '{argv[_];}' .
weggli '{envp[_];}' .
```
