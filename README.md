#  Order-Revealing Encryption in Java

Implements a Java wrapper for the
[ORE-Scheme presented by Chenet et al.](https://crypto.stanford.edu/ore/). The C implementation can be found 
[here](https://github.com/kevinlewi/fastore).

## Prerequisites 
Make sure you have the following installed:
 * [CMake](https://cmake.org/)
 * [GMP 5](http://gmplib.org/)
 * [OpenSSL](http://www.openssl.org/source/)
 * [Maven](https://maven.apache.org/)
 * Java JDK 1.8
 
## Build 

C code:
```
cd native
cmake .
make
./out/ore-test
``` 

Java jar package:
```
mvn package
``` 

## Example usage

```java
OREKey key = ORE.generateKey();
ORE ore = ORE.getDefaultOREInstance(key);
long val1 = 10, val2 = 20;
long val1Dec, val2Dec;
int cmp;
ORECiphertext ctxt1, ctxt2;

ctxt1 = ore.encrypt(val1);
ctxt2 = ore.encrypt(val2);
cmp = ctxt1.compareTo(ctxt2);
assertEquals(cmp, -1);
cmp = ctxt2.compareTo(ctxt1);
assertEquals(cmp, 1);
cmp = ctxt1.compareTo(ctxt1);
assertEquals(cmp, 0);

val1Dec = ore.decrypt(ctxt1);
val2Dec = ore.decrypt(ctxt2);
assertEquals(val1Dec, val1);
assertEquals(val2Dec, val2);

``` 