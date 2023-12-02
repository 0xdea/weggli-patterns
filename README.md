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

### call to insecure API functions (CWE-120, CWE-242, CWE-676)
```
weggli -R 'func=^get' '{$func(_);}' .
weggli -R 'func=^st(r|p)(cpy|cat)' '{$func(_);}' .
weggli -R 'func=^wc(s|p)(cpy|cat)' '{$func(_);}' .
weggli -R 'func=sprintf$' '{$func(_);}' .
weggli -R 'func=scanf$' '{$func(_);}' .
```

### incorrect use of strncat (CWE-193, CWE-787)
```
weggli '{strncat(_,_,sizeof(_));}' .
weggli '{strncat(_,_,strlen(_));}' .
weggli '{strncat($dst,$src,sizeof($dst)-strlen($dst));}' .

# this won't work due to current limitations in the query language
# weggli '{_ $buf[$len]; strncat($buf,_,$len);}' .
# https://github.com/weggli-rs/weggli/issues/59
```

### destination buffer access using size of source buffer (CWE-806)
```
weggli -R 'func=cpy' '{$func(_,$src,_($src));}' .

# this won't work due to current limitations in the query language
# weggli -R 'func=cpy' '{_ $src[$len]; $func($dst,$src,$len);}' .
# https://github.com/weggli-rs/weggli/issues/59
```

### use of sizeof() on a pointer type (CWE-467)
```
weggli '{_* $p; sizeof($p);}' .
weggli '{_* $p = _; sizeof($p);}' .
weggli '_ $func(_* $p) {sizeof($p);}'
```

### lack of explicit NUL-termination after strncpy(), etc. (CWE-170)
```
weggli -R 'func=ncpy' '{$func($buf,_); not: $buf[_]=_;}' .

# some variants
# read(), readlink(), fread(), memcpy(), etc.
```

### off-by-one error (CWE-193)

TBD

### use of pointer subtraction to determine size (CWE-469)

TBD

### potentially unsafe use of the return value of snprintf(), etc. (CWE-787)
```
weggli -R 'func=(nprintf|lcpy|lcat)' '{$ret=$func(_);}' .
```

### direct write into buffer allocated on the stack (CWE-121)
```
weggli -R 'func=(cpy|cat|memmove|memset|sn?printf)' '{_ $buf[_]; $func($buf);}' .

# some variants
# bcopy
# gets, fgets, getwd, getcwd, fread
# read, pread, recv, recvfrom
# simple assignment
```

## integer overflows

### signed or short sizes, lengths, offsets, counts (CWE-190, CWE-680)
```
weggli '{short _;}' .
weggli '{int _;}' .

# some variants
# short int
# unsigned short
# unsigned short int
# int
```

### casting the return value of strlen(), wcslen() to short (CWE-190, CWE-680)
```
weggli '{short $len; $len=strlen(_);}' .
weggli '{short $len; $len=wcslen(_);}' .

# some variants
# short int
# unsigned short
# unsigned short int
```

## format strings

### find printf(), scanf(), syslog() family functions (CWE-134)
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

### use of uninitialized pointers (CWE-457, CWE-824, CWE-908)
```
weggli '{_* $p; not: $p =_; not: $func1(&$p); $func2($p);}' .
weggli '{_ $p[]; not: $p =_; not: $func1(&$p); $func2($p);}' .
```

## command injection

TBD

## race conditions

TBD

## privilege management

### unchecked return code of setuid() and seteuid() (CWE-252)
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
