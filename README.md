## emit-jvm-bytecode

Lightweight library for **programmatically** generating Java class files and JVM bytecode without external dependencies, i.e. no JNI wrappers. This library itself only has a dependency on [`byteorder`](https://crates.io/crates/byteorder) for endianness.

### Installation

Add the dependency below to your `Cargo.toml`:

```toml
[dependencies]
emit-jvm-bytecode = "0.1.0"
```

### Validating test class files

The test cases may emit class files corresponding to the stub bytecode.

```shell
cargo test
```

Validate the files by running against `javap`.

```shell
javap -c <path>
```

The hex dump can offer a better view of the bytecode as it is represented in memory.

```shell
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
