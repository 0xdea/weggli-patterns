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

Blog post:  
https://security.humanativaspa.it/a-collection-of-weggli-patterns-for-c-cpp-vulnerability-research

See also:  
https://github.com/weggli-rs/weggli  
https://dustri.org/b/playing-with-weggli.html  
https://github.com/plowsec/weggli-patterns  
https://github.com/synacktiv/Weggli_rules_SSTIC2023  
https://twitter.com/richinseattle/status/1729654184633327720  

## buffer overflows

### call to unbounded copy functions (CWE-120, CWE-242, CWE-676)
```
weggli -R 'func=gets$' '{$func();}' .
weggli -R 'func=st(r|p)(cpy|cat)$' '{$func();}' .
weggli -R 'func=wc(s|p)(cpy|cat)$' '{$func();}' .
weggli -R 'func=sprintf$' '{$func();}' .
weggli -R 'func=scanf$' '{$func();}' .
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
weggli -R 'func=cpy$' '{$func(_,$src,_($src));}' .

# this won't work due to current limitations in the query language
# weggli -R 'func=cpy$' '{_ $src[$len]; $func($dst,$src,$len);}' .
# https://github.com/weggli-rs/weggli/issues/59
```

### use of sizeof() on a pointer type (CWE-467)
```
weggli '{_* $p; sizeof($p);}' .
weggli '{_* $p=_; sizeof($p);}' .
weggli '_ $func(_* $p) {sizeof($p);}' .
```

### lack of explicit NUL-termination after strncpy(), etc. (CWE-170)
```
weggli -R 'func=ncpy$' '{$func($buf,_); not: $buf[_]=_;}' .

# some variants: memcpy, read, readlink, fread, etc.
```

### off-by-one error (CWE-193)
```
weggli '{$buf[sizeof($buf)];}' .
weggli '{_ $buf[$len]; $buf[$len]=_;}' .
weggli '{strlen($src)>sizeof($dst);}' .
weggli '{strlen($src)<=sizeof($dst);}' .
weggli '{sizeof($dst)<strlen($src);}' .
weggli '{sizeof($dst)>=strlen($src);}' .
weggli '{$buf[strlen($buf)-1];}' .
weggli '{malloc(strlen($buf));}' .

# < should also cover > as <= should also cover >= 
# however, keep all cases just to be sure
```

### use of pointer subtraction to determine size (CWE-469)
```
weggli '{_* $p1; $p1-$p2;}' .
weggli '{_* $p2; $p1-$p2;}' .
weggli '{_* $p1=_; $p1-$p2;}' .
weggli '{_* $p2=_; $p1-$p2;}' .
weggli '_ $func(_* $p1) {$p1-$p2;}' .
weggli '_ $func(_* $p2) {$p1-$p2;}' .
```

### potentially unsafe use of the return value of snprintf(), etc. (CWE-787)
```
weggli -R 'func=(nprintf|lcpy|lcat)$' '{$ret=$func();}' .
```

### direct write into buffer allocated on the stack (CWE-121)
```
weggli -R 'func=(cpy|cat|memmove|memset|sn?printf)$' '{_ $buf[_]; $func($buf,_);}' .
weggli '{_ $buf[_]; $buf[_]=_;}' .

# some variants: bcopy, gets, fgets, getwd, getcwd, fread, read, pread, recv, recvfrom, etc.
```

## integer overflows

### incorrect unsigned comparison (CWE-697)
```
weggli -R '$type=(unsigned|size_t)' '{$type $var; $var<0;}' .
weggli -R '$type=(unsigned|size_t)' '{$type $var; $var<=0;}' .
weggli -R '$type=(unsigned|size_t)' '{$type $var; $var>=0;}' .
weggli -R '$type=(unsigned|size_t)' '{$type $var=_; $var<0;}' .
weggli -R '$type=(unsigned|size_t)' '{$type $var=_; $var<=0;}' .
weggli -R '$type=(unsigned|size_t)' '{$type $var=_; $var>=0;}' .

# < should also cover > as <= should also cover >= 
# however, keep all cases just to be sure
```

### signed/unsigned conversion (CWE-195, CWE-196)
```
weggli -R '$copy=(cpy|ncat)$' '{int $len; $copy(_,_,$len);}' .
weggli -R '$copy=(cpy|ncat)$' '{int $len=_; $copy(_,_,$len);}' .
weggli -R '$copy=(cpy|ncat)$' '_ $func(int $len) {$copy(_,_,$len);}' .

weggli -R '$copy=nprintf$' '{int $len; $copy(_,$len);}' .
weggli -R '$copy=nprintf$' '{int $len=_; $copy(_,$len);}' .
weggli -R '$copy=nprintf$' '_ $func(int $len) {$copy(_,$len);}' .

weggli -R '$type=(unsigned|size_t)' '{$type $var1; int $var2; $var2=_($var1);}' .
weggli -R '$type=(unsigned|size_t)' '{$type $var1; int $var2; $var1=_($var2);}' .
weggli -R '$type=(unsigned|size_t)' '{$type $var1; int $var2=_($var1);}' .
weggli -R '$type=(unsigned|size_t)' '{int $var1; $type $var2; $var2=_($var1);}' .
weggli -R '$type=(unsigned|size_t)' '{int $var1; $type $var2; $var1=_($var2);}' .
weggli -R '$type=(unsigned|size_t)' '{int $var1=_; $type $var2=_($var1);}' .

weggli -R '$type=(unsigned|size_t)' '_ $func(int $var2) {$type $var1; $var1=_($var2);}' .
weggli -R '$type=(unsigned|size_t)' '_ $func(int $var2) {$type $var1=_($var2);}' .

weggli -R '$type=(unsigned|size_t)' '$type $func(_) {int $var; return $var;}' .
weggli -R '$type=(unsigned|size_t)' 'int $func(_) {$type $var; return $var;}' .

# there are many possible variants...
```

### integer truncation (CWE-197)
```
weggli -R 'type=(short|int|long)' '{$type $large; char $narrow; $narrow = $large; }' .
weggli -R 'type=(short|int|long)' '{$type $large; char $narrow = $large; }' .
weggli -R 'type=(int|long)' '{$type $large; short $narrow; $narrow = $large; }' .
weggli -R 'type=(int|long)' '{$type $large; short $narrow = $large; }' .
weggli '{long $large; int $narrow; $narrow = $large; }' .
weggli '{long $large; int $narrow = $large; }' .

weggli -R 'type=(short|int|long)' '_ $func($type $large) {char $narrow; $narrow = $large; }' .
weggli -R 'type=(short|int|long)' '_ $func($type $large) {char $narrow = $large; }' .
weggli -R 'type=(int|long)' '_ $func($type $large) {short $narrow; $narrow = $large; }' .
weggli -R 'type=(int|long)' '_ $func($type $large) {short $narrow = $large; }' .
weggli '_ $func(long $large) {int $narrow; $narrow = $large; }' .
weggli '_ $func(long $large) {int $narrow = $large; }' .

# there are many possible variants...
```

### use of signed or short sizes, lengths, offsets, counts (CWE-190, CWE-680)
```
weggli '{short _;}' .
weggli '{int _;}' .

# some variants: short int, unsigned short, unsigned short int, int
```

### cast of the return value of strlen(), wcslen() to short (CWE-190, CWE-680)
```
weggli -R 'func=(str|wcs)len$' '{short $len; $len=$func();}' .

# some variants: short int, unsigned short, unsigned short int
```

### integer wraparound (CWE-128, CWE-131, CWE-190, CWE-680)
```
weggli -R 'func=(v|m)alloc$' '{$func(_*_);}' .
weggli -R 'func=(v|m)alloc$' '{$func(_+_);}' .
weggli -R 'func=(v|m)alloc$' '{$n=_*_; $func($n);}' .
weggli -R 'func=(v|m)alloc$' '{$n=_+_; $func($n);}' .

weggli -R 'func=(c|re|aligned_)allocf?$' '{$func(_*_);}' .
weggli -R 'func=(c|re|aligned_)allocf?$' '{$func(_+_);}' .
weggli -R 'func=(c|re|aligned_)allocf?$' '{$n=_*_; $func($buf,$n);}' .
weggli -R 'func=(c|re|aligned_)allocf?$' '{$n=_+_; $func($buf,$n);}' .

weggli '{$x>_||($x+$y)>_;}' .
weggli '{$x>=_||($x+$y)>_;}' .
weggli '{$x>_||($x+$y)>=_;}' .
weggli '{$x>=_||($x+$y)>=_;}' .
weggli '{$x<_&&($x+$y)<_;}' .
weggli '{$x<=_&&($x+$y)<_;}' .
weggli '{$x<_&&($x+$y)<=_;}' .
weggli '{$x<=_&&($x+$y)<=_;}' .

weggli '{$x>_||($x*$y)>_;}' .
weggli '{$x>=_||($x*$y)>_;}' .
weggli '{$x>_||($x*$y)>=_;}' .
weggli '{$x>=_||($x*$y)>=_;}' .
weggli '{$x<_&&($x*$y)<_;}' .
weggli '{$x<=_&&($x*$y)<_;}' .
weggli '{$x<_&&($x*$y)<=_;}' .
weggli '{$x<=_&&($x*$y)<=_;}' .

# < should also cover > as <= should also cover >= 
# however, keep all cases just to be sure
```

## format strings

### call to printf(), scanf(), syslog() family functions (CWE-134)
```
weggli -R 'func=(printf|scanf|syslog)$' '{$func();}' .

# some variants: printk, warn, vwarn, warnx, vwarnx, err, verr, errx, verrx, warnc, vwarnc, errc, verrc
```

## memory management

### call to alloca() (CWE-676, CWE-1325)
```
weggli -R 'func=alloca$' '{$func();}' .
```

### use after free (CWE-416)
```
weggli '{free($ptr); not:$ptr=_; not:free($ptr); _($ptr);}' use-after-free.c
```

### double free (CWE-415)
```
weggli '{free($ptr); not:$ptr=_; free($ptr);}' .
```

### calling free() on memory not allocated in the heap (CWE-590)
```
weggli '{_ $ptr[]; free($ptr);}' .
weggli '{_ $ptr[]=_; free($ptr);}' .

weggli '{_ $ptr[]; $ptr2=$ptr; free($ptr2);}' .
weggli '{_ $ptr[]=_; $ptr2=$ptr; free($ptr2);}' .

weggli '{_ $var; free(&$var);}' .
weggli '{_ $var=_; free(&$var);}' .
weggli '{_ $var[]; free(&$var);}' .
weggli '{_ $var[]=_; free(&$var);}' .
weggli '{_ *$var; free(&$var);}' .
weggli '{_ *$var=_; free(&$var);}' .
```

### unchecked return code of malloc(), etc. (CWE-252, CWE-690)
```
weggli -R 'func=(m|c|re)alloc$' '{$ret=$func(); not:if(_($ret)){};}' .
```

### returning the address of a stack-allocated variable (CWE-562)
```
weggli '{_ $ptr[]; return $ptr;}' .
weggli '{_ $ptr[]=_; return $ptr;}' .

weggli '{_ $ptr[]; $ptr2=$ptr; return $ptr2;}' .
weggli '{_ $ptr[]=_; $ptr2=$ptr; return $ptr2;}' .

weggli '{_ $var; return &$var;}' .
weggli '{_ $var=_; return &$var;}' .
weggli '{_ $var[]; return &$var;}' .
weggli '{_ $var[]=_; return &$var;}' .
weggli '{_ *$var; return &$var;}' .
weggli '{_ *$var=_; return &$var;}' .
```

### call to putenv() with a stack-allocated variable (CWE-686)
```
weggli '{_ $ptr[]; putenv($ptr);}' .
weggli '{_ $ptr[]=_; putenv($ptr);}' .

weggli '{_ $ptr[]; $ptr2=$ptr; putenv($ptr2);}' .
weggli '{_ $ptr[]=_; $ptr2=$ptr; putenv($ptr2);}' .
```

### exposure of underlying memory addresses (CWE-200, CWE-209, CWE-497)
```
weggli -R 'func=printf$' -R 'fmt=(.*%\w*x.*|.*%\w*X.*|.*%\w*p.*)' '{$func("$fmt");}' .
```

### mismatched memory management routines (CWE-762)
```
weggli -R 'func=(m|c|re)alloc$|strdn?up$' '{not:$ptr=$func(); free($ptr);}' .

weggli --cpp -R 'func=(m|c|re)alloc$|strn?dup$' '{not:$ptr=$func(); free($ptr);}' .
weggli --cpp '{not:$ptr=new $obj; delete $ptr;}' .

# apparently, delete[] is not supported so this won't work properly
# weggli --cpp '{not:$ptr=new $obj[$len]; delete[] $ptr;}' .
```

### use of uninitialized pointers (CWE-457, CWE-824, CWE-908)
```
weggli '{_* $p; not: $p =_; not: $func(&$p); _($p);}' .
```

## command injection

### call to system(), popen() (CWE-78, CWE-88, CWE-676)
```
weggli -R 'func=(system|popen)$' '{$func();}' .
```

## race conditions

### call to access(), stat(), lstat() (CWE-367)
```
weggli -R 'func=(access|l?stat)$' '{$func();}' .
```

### call to mktemp(), tmpnam(), tempnam() (CWE-377)
```
weggli -R 'func=(mktemp|te?mpnam)$' '{$func();}' .
```

### call to signal() (CWE-364, CWE-479, CWE-828)
```
weggli -R 'func=signal$' '{$func();}' .
```

## privilege management

### privilege management functions called in the wrong order (CWE-696)
```
weggli '{not:setuid(0); setuid(); setgid();}' .
weggli '{not:seteuid(0); seteuid(); not:seteuid(0); setegid();}' .
weggli '{not:seteuid(0); seteuid(); not:seteuid(0); setuid();}' .
weggli '{not:seteuid(0); seteuid(); not:seteuid(0); seteuid();}' .
```

### unchecked return code of setuid(), seteuid() (CWE-252)
```
weggli -R 'func=sete?uid$' '{strict: $func();}' .
```

## miscellaneous

### wrong order of arguments in call to memset() 
```
weggli -R 'func=memset(_explicit)?$' '{$func(_,_,0);}' .
weggli -R 'func=memset(_explicit)?$' '{$func(_,sizeof(_),_);}' .
```

### call to rand(), srand() (CWE-330, CWE-338)
```
weggli -R 'func=s?rand$' '{$func();}'
```

### source and destination overlap in sprintf(), snprintf()
```
weggli -R 'func=sn?printf$' '{$func($dst,_,$dst);}' .
weggli -R 'func=sn?printf$' '{$func($dst,_,_,$dst);}' .
weggli -R 'func=sn?printf$' '{$func($dst,_,_,_,$dst);}' .

# and so on...
```

### size check implemented with an assertion macro
```
weggli -R 'assert=(?i)^\w*assert\w*\s*$' '{$assert(_<_);}' .
weggli -R 'assert=(?i)^\w*assert\w*\s*$' '{$assert(_<=_);}' .
weggli -R 'assert=(?i)^\w*assert\w*\s*$' '{$assert(_>_);}' .
weggli -R 'assert=(?i)^\w*assert\w*\s*$' '{$assert(_>=_);}' .

# < should also cover > as <= should also cover >= 
# however, keep all cases just to be sure
```

### unchecked return code of scanf(), etc. (CWE-252)
```
weggli -R 'func=scanf$' '{strict: $func();}' .
```

### call to atoi(), atol(), atof(), atoll()
```
weggli -R 'func=ato(i|ll?|f)$' '{$func();}' .
```

### command-line argument or environment variable access
```
weggli -R 'var=(argv|envp)' '{$var[_];}' .
```

### missing default case in a switch construct (CWE-478)
```
weggli -l '{not: default:_; case _:_; not: default:_;}' .

# -l might be overkill and lead to missing additional instances in the same function
```

### missing break or equivalent statement in a switch construct (CWE-484)

TBD

### missing return statement in a non-void function (CWE-393, CWE-394)

TBD

### typos with security implications (CWE-480, CWE-481, CWE-482, CWE-483)

TBD

### keywords that suggest the presence of bugs

TBD
