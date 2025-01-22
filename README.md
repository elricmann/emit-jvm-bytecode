## emit-jvm-bytecode

Lightweight library for **programmatically** generating Java class files and JVM bytecode without external dependencies, i.e. no JNI wrappers. This library itself only has a dependency on [`byteorder`](https://crates.io/crates/byteorder) for endianness.

The only other alternatives are [ASM](https://asm.ow2.io/asm4-guide.pdf) package (requires JDK) or using binary instrumentation tools that rely on JNI wrappers.

### Installation

Add the dependency below to `Cargo.toml`:

```toml
[dependencies]
emit-jvm-bytecode = "0.1.0"
```

### Quick Overview

The bytecode builder is separate from the class generating functionality which means it can be used separately.

```rust
let mut builder = BytecodeBuilder::new();

builder.emit_u8(opcodes::ALOAD_0);
builder.emit_u16(0x1234);
builder.emit_i32(0x12345678);

let bytes = builder.get_bytes();
assert_eq!(bytes[0], opcodes::ALOAD_0);
assert_eq!(bytes[1..3], [0x12, 0x34]);
assert_eq!(bytes[3..7], [0x12, 0x34, 0x56, 0x78]);
```

When the bytecode is inlined into the class file then it will generate a representation.

```java
public class MainTest {
  public static void main(java.lang.String[]);
    Code:
       0: getstatic     #10                 // Field java/lang/System.out:Ljava/io/PrintStream;
       3: ldc           #18                 // String Hello, world!
       5: invokevirtual #16                 // Method java/io/PrintStream.println:(Ljava/lang/String;)V
       8: return
}
```

Executing the class file may result in errors but are usually followed by the corresponding bytecode. In this case, the bytecode generated is not in line with the expected behavior, there are no checks done to ensure that this is actually valid.

```shell
Error: Unable to initialize main class Main
Caused by: java.lang.VerifyError: Operand stack overflow
Exception Details:
  Location:
    Main.main()V @3: ldc
  Reason:
    Exceeded max stack size.
  Current Frame:
    bci: @3
    flags: { }
    locals: { }
    stack: { 'java/io/PrintStream' }
  Bytecode:
    0000000: b200 0a12 12b6 0010 b1
```

### Running Tests

The test cases may emit class files corresponding to the stub bytecode.

```shell
cargo test
```

Validate the files by running against `javap`.

```shell
javap -c <path>
```

Optionally silence verbose `_JAVA_OPTIONS`.

```shell
unset _JAVA_OPTIONS
```

The hex dump can offer a better view of the bytecode as it is represented in memory.

```c
$ hexdump -C test/EmptyTest.class

00000000  ca fe ba be 00 00 00 34  00 05 01 00 0e 45 6d 70  |.......4.....Emp|
00000010  74 79 54 65 73 74 43 6c  61 73 73 07 00 01 01 00  |tyTestClass.....|
00000020  10 6a 61 76 61 2f 6c 61  6e 67 2f 4f 62 6a 65 63  |.java/lang/Objec|
00000030  74 07 00 03 00 21 00 02  00 04 00 00 00 00 00 00  |t....!..........|
00000040  00 00                                             |..|
00000042
```

Refer to the tests in [`src/lib.rs`](https://github.com/elricmann/emit-jvm-bytecode/blob/main/src/lib.rs) for more cases.

### Related

- [`wasm-emit-text`](https://github.com/elricmann/wasm-emit-text) - programmatically generate WebAssembly text modules.

### License

Copyright © 2025 Elric Neumann. MIT License.
