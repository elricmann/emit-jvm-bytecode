// Copyright (c) 2025 Elric Neumann. All rights reserved. MIT license.
use byteorder::{BigEndian, WriteBytesExt};
use std::fs::File;
use std::io::{self, Write};

pub mod opcodes {
    // constants
    pub const NOP: u8 = 0x00;
    pub const ACONST_NULL: u8 = 0x01;
    pub const ICONST_M1: u8 = 0x02;
    pub const ICONST_0: u8 = 0x03;
    pub const ICONST_1: u8 = 0x04;
    pub const ICONST_2: u8 = 0x05;
    pub const ICONST_3: u8 = 0x06;
    pub const ICONST_4: u8 = 0x07;
    pub const ICONST_5: u8 = 0x08;
    pub const LCONST_0: u8 = 0x09;
    pub const LCONST_1: u8 = 0x0a;
    pub const FCONST_0: u8 = 0x0b;
    pub const FCONST_1: u8 = 0x0c;
    pub const FCONST_2: u8 = 0x0d;
    pub const DCONST_0: u8 = 0x0e;
    pub const DCONST_1: u8 = 0x0f;
    pub const BIPUSH: u8 = 0x10;
    pub const SIPUSH: u8 = 0x11;
    pub const LDC: u8 = 0x12;
    pub const LDC_W: u8 = 0x13;
    pub const LDC2_W: u8 = 0x14;

    // loads
    pub const ILOAD: u8 = 0x15;
    pub const LLOAD: u8 = 0x16;
    pub const FLOAD: u8 = 0x17;
    pub const DLOAD: u8 = 0x18;
    pub const ALOAD: u8 = 0x19;
    pub const ILOAD_0: u8 = 0x1a;
    pub const ILOAD_1: u8 = 0x1b;
    pub const ILOAD_2: u8 = 0x1c;
    pub const ILOAD_3: u8 = 0x1d;
    pub const LLOAD_0: u8 = 0x1e;
    pub const LLOAD_1: u8 = 0x1f;
    pub const LLOAD_2: u8 = 0x20;
    pub const LLOAD_3: u8 = 0x21;
    pub const FLOAD_0: u8 = 0x22;
    pub const FLOAD_1: u8 = 0x23;
    pub const FLOAD_2: u8 = 0x24;
    pub const FLOAD_3: u8 = 0x25;
    pub const DLOAD_0: u8 = 0x26;
    pub const DLOAD_1: u8 = 0x27;
    pub const DLOAD_2: u8 = 0x28;
    pub const DLOAD_3: u8 = 0x29;
    pub const ALOAD_0: u8 = 0x2a;
    pub const ALOAD_1: u8 = 0x2b;
    pub const ALOAD_2: u8 = 0x2c;
    pub const ALOAD_3: u8 = 0x2d;
    pub const IALOAD: u8 = 0x2e;
    pub const LALOAD: u8 = 0x2f;
    pub const FALOAD: u8 = 0x30;
    pub const DALOAD: u8 = 0x31;
    pub const AALOAD: u8 = 0x32;
    pub const BALOAD: u8 = 0x33;
    pub const CALOAD: u8 = 0x34;
    pub const SALOAD: u8 = 0x35;

    // stores
    pub const ISTORE: u8 = 0x36;
    pub const LSTORE: u8 = 0x37;
    pub const FSTORE: u8 = 0x38;
    pub const DSTORE: u8 = 0x39;
    pub const ASTORE: u8 = 0x3a;
    pub const ISTORE_0: u8 = 0x3b;
    pub const ISTORE_1: u8 = 0x3c;
    pub const ISTORE_2: u8 = 0x3d;
    pub const ISTORE_3: u8 = 0x3e;
    pub const LSTORE_0: u8 = 0x3f;
    pub const LSTORE_1: u8 = 0x40;
    pub const LSTORE_2: u8 = 0x41;
    pub const LSTORE_3: u8 = 0x42;
    pub const FSTORE_0: u8 = 0x43;
    pub const FSTORE_1: u8 = 0x44;
    pub const FSTORE_2: u8 = 0x45;
    pub const FSTORE_3: u8 = 0x46;
    pub const DSTORE_0: u8 = 0x47;
    pub const DSTORE_1: u8 = 0x48;
    pub const DSTORE_2: u8 = 0x49;
    pub const DSTORE_3: u8 = 0x4a;
    pub const ASTORE_0: u8 = 0x4b;
    pub const ASTORE_1: u8 = 0x4c;
    pub const ASTORE_2: u8 = 0x4d;
    pub const ASTORE_3: u8 = 0x4e;
    pub const IASTORE: u8 = 0x4f;
    pub const LASTORE: u8 = 0x50;
    pub const FASTORE: u8 = 0x51;
    pub const DASTORE: u8 = 0x52;
    pub const AASTORE: u8 = 0x53;
    pub const BASTORE: u8 = 0x54;
    pub const CASTORE: u8 = 0x55;
    pub const SASTORE: u8 = 0x56;

    // stack
    pub const POP: u8 = 0x57;
    pub const POP2: u8 = 0x58;
    pub const DUP: u8 = 0x59;
    pub const DUP_X1: u8 = 0x5a;
    pub const DUP_X2: u8 = 0x5b;
    pub const DUP2: u8 = 0x5c;
    pub const DUP2_X1: u8 = 0x5d;
    pub const DUP2_X2: u8 = 0x5e;
    pub const SWAP: u8 = 0x5f;

    // math
    pub const IADD: u8 = 0x60;
    pub const LADD: u8 = 0x61;
    pub const FADD: u8 = 0x62;
    pub const DADD: u8 = 0x63;
    pub const ISUB: u8 = 0x64;
    pub const LSUB: u8 = 0x65;
    pub const FSUB: u8 = 0x66;
    pub const DSUB: u8 = 0x67;
    pub const IMUL: u8 = 0x68;
    pub const LMUL: u8 = 0x69;
    pub const FMUL: u8 = 0x6a;
    pub const DMUL: u8 = 0x6b;
    pub const IDIV: u8 = 0x6c;
    pub const LDIV: u8 = 0x6d;
    pub const FDIV: u8 = 0x6e;
    pub const DDIV: u8 = 0x6f;
    pub const IREM: u8 = 0x70;
    pub const LREM: u8 = 0x71;
    pub const FREM: u8 = 0x72;
    pub const DREM: u8 = 0x73;
    pub const INEG: u8 = 0x74;
    pub const LNEG: u8 = 0x75;
    pub const FNEG: u8 = 0x76;
    pub const DNEG: u8 = 0x77;
    pub const ISHL: u8 = 0x78;
    pub const LSHL: u8 = 0x79;
    pub const ISHR: u8 = 0x7a;
    pub const LSHR: u8 = 0x7b;
    pub const IUSHR: u8 = 0x7c;
    pub const LUSHR: u8 = 0x7d;
    pub const IAND: u8 = 0x7e;
    pub const LAND: u8 = 0x7f;
    pub const IOR: u8 = 0x80;
    pub const LOR: u8 = 0x81;
    pub const IXOR: u8 = 0x82;
    pub const LXOR: u8 = 0x83;
    pub const IINC: u8 = 0x84;

    // conversions
    pub const I2L: u8 = 0x85;
    pub const I2F: u8 = 0x86;
    pub const I2D: u8 = 0x87;
    pub const L2I: u8 = 0x88;
    pub const L2F: u8 = 0x89;
    pub const L2D: u8 = 0x8a;
    pub const F2I: u8 = 0x8b;
    pub const F2L: u8 = 0x8c;
    pub const F2D: u8 = 0x8d;
    pub const D2I: u8 = 0x8e;
    pub const D2L: u8 = 0x8f;
    pub const D2F: u8 = 0x90;
    pub const I2B: u8 = 0x91;
    pub const I2C: u8 = 0x92;
    pub const I2S: u8 = 0x93;

    // comparisons
    pub const LCMP: u8 = 0x94;
    pub const FCMPL: u8 = 0x95;
    pub const FCMPG: u8 = 0x96;
    pub const DCMPL: u8 = 0x97;
    pub const DCMPG: u8 = 0x98;
    pub const IFEQ: u8 = 0x99;
    pub const IFNE: u8 = 0x9a;
    pub const IFLT: u8 = 0x9b;
    pub const IFGE: u8 = 0x9c;
    pub const IFGT: u8 = 0x9d;
    pub const IFLE: u8 = 0x9e;
    pub const IF_ICMPEQ: u8 = 0x9f;
    pub const IF_ICMPNE: u8 = 0xa0;
    pub const IF_ICMPLT: u8 = 0xa1;
    pub const IF_ICMPGE: u8 = 0xa2;
    pub const IF_ICMPGT: u8 = 0xa3;
    pub const IF_ICMPLE: u8 = 0xa4;
    pub const IF_ACMPEQ: u8 = 0xa5;
    pub const IF_ACMPNE: u8 = 0xa6;

    // control
    pub const GOTO: u8 = 0xa7;
    pub const JSR: u8 = 0xa8;
    pub const RET: u8 = 0xa9;
    pub const TABLESWITCH: u8 = 0xaa;
    pub const LOOKUPSWITCH: u8 = 0xab;
    pub const IRETURN: u8 = 0xac;
    pub const LRETURN: u8 = 0xad;
    pub const FRETURN: u8 = 0xae;
    pub const DRETURN: u8 = 0xaf;
    pub const ARETURN: u8 = 0xb0;
    pub const RETURN: u8 = 0xb1;

    // references
    pub const GETSTATIC: u8 = 0xb2;
    pub const PUTSTATIC: u8 = 0xb3;
    pub const GETFIELD: u8 = 0xb4;
    pub const PUTFIELD: u8 = 0xb5;
    pub const INVOKEVIRTUAL: u8 = 0xb6;
    pub const INVOKESPECIAL: u8 = 0xb7;
    pub const INVOKESTATIC: u8 = 0xb8;
    pub const INVOKEINTERFACE: u8 = 0xb9;
    pub const INVOKEDYNAMIC: u8 = 0xba;
    pub const NEW: u8 = 0xbb;
    pub const NEWARRAY: u8 = 0xbc;
    pub const ANEWARRAY: u8 = 0xbd;
    pub const ARRAYLENGTH: u8 = 0xbe;
    pub const ATHROW: u8 = 0xbf;
    pub const CHECKCAST: u8 = 0xc0;
    pub const INSTANCEOF: u8 = 0xc1;
    pub const MONITORENTER: u8 = 0xc2;
    pub const MONITOREXIT: u8 = 0xc3;

    // extended
    pub const WIDE: u8 = 0xc4;
    pub const MULTIANEWARRAY: u8 = 0xc5;
    pub const IFNULL: u8 = 0xc6;
    pub const IFNONNULL: u8 = 0xc7;
    pub const GOTO_W: u8 = 0xc8;
    pub const JSR_W: u8 = 0xc9;

    // reserved
    pub const BREAKPOINT: u8 = 0xca;
    pub const IMPDEP1: u8 = 0xfe;
    pub const IMPDEP2: u8 = 0xff;
}

#[derive(Debug)]
pub struct ConstantPoolInfo {
    tag: u8,
    info: Vec<u8>,
}

#[derive(Debug)]
pub struct FieldInfo {
    access_flags: u16,
    name_index: u16,
    descriptor_index: u16,
    attributes_count: u16,
    attributes: Vec<AttributeInfo>,
}

#[derive(Debug)]
pub struct MethodInfo {
    access_flags: u16,
    name_index: u16,
    descriptor_index: u16,
    attributes_count: u16,
    attributes: Vec<AttributeInfo>,
}

#[derive(Debug)]
pub struct AttributeInfo {
    attribute_name_index: u16,
    info: Vec<u8>,
}

#[derive(Debug)]
pub struct ClassFile {
    magic: u32,
    minor_version: u16,
    major_version: u16,
    constant_pool_count: u16,
    constant_pool: Vec<ConstantPoolInfo>,
    access_flags: u16,
    this_class: u16,
    super_class: u16,
    interfaces_count: u16,
    interfaces: Vec<u16>,
    fields_count: u16,
    fields: Vec<FieldInfo>,
    methods_count: u16,
    methods: Vec<MethodInfo>,
    attributes_count: u16,
    attributes: Vec<AttributeInfo>,
}

impl ClassFile {
    pub fn new() -> Self {
        ClassFile {
            magic: 0xCAFEBABE,
            minor_version: 0,
            major_version: 52,
            constant_pool_count: 1,
            constant_pool: Vec::new(),
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces_count: 0,
            interfaces: Vec::new(),
            fields_count: 0,
            fields: Vec::new(),
            methods_count: 0,
            methods: Vec::new(),
            attributes_count: 0,
            attributes: Vec::new(),
        }
    }

    pub fn add_constant(&mut self, tag: u8, info: Vec<u8>) -> u16 {
        self.constant_pool.push(ConstantPoolInfo { tag, info });
        self.constant_pool_count += 1;
        self.constant_pool_count - 1
    }

    pub fn add_field(&mut self, field: FieldInfo) {
        self.fields.push(field);
        self.fields_count += 1;
    }

    pub fn add_method(&mut self, method: MethodInfo) {
        self.methods.push(method);
        self.methods_count += 1;
    }

    pub fn add_attribute(&mut self, attribute: AttributeInfo) {
        self.attributes.push(attribute);
        self.attributes_count += 1;
    }

    // Cf: https://elric.pl/blog/endianness-jvm

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u32::<BigEndian>(self.magic)?;
        writer.write_u16::<BigEndian>(self.minor_version)?;
        writer.write_u16::<BigEndian>(self.major_version)?;
        writer.write_u16::<BigEndian>(self.constant_pool_count)?;

        for constant in &self.constant_pool {
            writer.write_u8(constant.tag)?;
            writer.write_all(&constant.info)?;
        }

        writer.write_u16::<BigEndian>(self.access_flags)?;
        writer.write_u16::<BigEndian>(self.this_class)?;
        writer.write_u16::<BigEndian>(self.super_class)?;
        writer.write_u16::<BigEndian>(self.interfaces_count)?;

        for interface in &self.interfaces {
            writer.write_u16::<BigEndian>(*interface)?;
        }

        writer.write_u16::<BigEndian>(self.fields_count)?;
        for field in &self.fields {
            writer.write_u16::<BigEndian>(field.access_flags)?;
            writer.write_u16::<BigEndian>(field.name_index)?;
            writer.write_u16::<BigEndian>(field.descriptor_index)?;
            writer.write_u16::<BigEndian>(field.attributes_count)?;

            for attr in &field.attributes {
                writer.write_u16::<BigEndian>(attr.attribute_name_index)?;
                writer.write_all(&attr.info)?;
            }
        }

        writer.write_u16::<BigEndian>(self.methods_count)?;
        for method in &self.methods {
            writer.write_u16::<BigEndian>(method.access_flags)?;
            writer.write_u16::<BigEndian>(method.name_index)?;
            writer.write_u16::<BigEndian>(method.descriptor_index)?;
            writer.write_u16::<BigEndian>(method.attributes_count)?;

            for attr in &method.attributes {
                writer.write_u16::<BigEndian>(attr.attribute_name_index)?;
                writer.write_all(&attr.info)?;
            }
        }

        writer.write_u16::<BigEndian>(self.attributes_count)?;
        for attr in &self.attributes {
            writer.write_u16::<BigEndian>(attr.attribute_name_index)?;
            writer.write_all(&attr.info)?;
        }

        Ok(())
    }
}

pub fn write_bytecode(class_file: &ClassFile, path: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    class_file.write(&mut file)
}

pub struct BytecodeBuilder {
    bytes: Vec<u8>,
}

impl BytecodeBuilder {
    pub fn new() -> Self {
        BytecodeBuilder { bytes: Vec::new() }
    }

    pub fn emit_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn emit_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn emit_i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn get_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytecode_builder() {
        let mut builder = BytecodeBuilder::new();

        builder.emit_u8(opcodes::ALOAD_0);
        builder.emit_u16(0x1234);
        builder.emit_i32(0x12345678);

        let bytes = builder.get_bytes();
        assert_eq!(bytes[0], opcodes::ALOAD_0);
        assert_eq!(bytes[1..3], [0x12, 0x34]);
        assert_eq!(bytes[3..7], [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_field() -> io::Result<()> {
        let mut class_file = ClassFile::new();

        let field = FieldInfo {
            access_flags: 0x0001, // ACC_PUBLIC
            name_index: 1,
            descriptor_index: 2,
            attributes_count: 0,
            attributes: Vec::new(),
        };

        class_file.add_field(field);

        assert_eq!(class_file.fields_count, 1);
        assert_eq!(class_file.fields[0].access_flags, 0x0001);

        Ok(())
    }

    #[test]
    fn test_method() -> io::Result<()> {
        let mut class_file = ClassFile::new();

        let method = MethodInfo {
            access_flags: 0x0001, // ACC_PUBLIC
            name_index: 1,
            descriptor_index: 2,
            attributes_count: 0,
            attributes: Vec::new(),
        };

        class_file.add_method(method);

        assert_eq!(class_file.methods_count, 1);
        assert_eq!(class_file.methods[0].access_flags, 0x0001);

        Ok(())
    }

    #[test]
    fn test_constant_pool_entries() -> io::Result<()> {
        let mut class_file = ClassFile::new();

        // different types of constant pool entries

        let utf8_entry = class_file.add_constant(1, {
            let mut info = Vec::new();
            info.extend_from_slice(&(4u16).to_be_bytes());
            info.extend_from_slice(b"Test");
            info
        });

        let _class_entry = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_entry.to_be_bytes());
            info
        });

        assert_eq!(class_file.constant_pool_count, 3);
        assert_eq!(class_file.constant_pool[0].tag, 1); // UTF-8
        assert_eq!(class_file.constant_pool[1].tag, 7); // class

        Ok(())
    }

    #[test]
    fn test_empty_class() -> io::Result<()> {
        let mut class_file = ClassFile::new();

        // 1. add the class name as UTF-8
        let utf8_class_name = class_file.add_constant(1, {
            let name = b"EmptyTestClass";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        // 2. add class info that references the UTF-8 entry
        let class_info = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_class_name.to_be_bytes());
            info
        });

        // 3. add the superclass (java/lang/Object) name as UTF-8
        let utf8_object = class_file.add_constant(1, {
            let name = b"java/lang/Object";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        // 4. add superclass info that references the Object UTF-8 entry
        let object_class = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_object.to_be_bytes());
            info
        });

        // class properties
        class_file.access_flags = 0x0021; // ACC_PUBLIC | ACC_SUPER
        class_file.this_class = class_info;
        class_file.super_class = object_class;

        // constant pool is 1-based so the count must be 5 /!\
        class_file.constant_pool_count = class_file.constant_pool.len() as u16 + 1;

        let test_path = "test/EmptyTest.class";
        write_bytecode(&class_file, test_path)?;

        Ok(())
    }

    #[test]
    fn test_class_with_method() -> io::Result<()> {
        let mut class_file = ClassFile::new();

        let utf8_class = class_file.add_constant(1, {
            let name = b"MethodTest";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let class_info = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_class.to_be_bytes());
            info
        });

        let utf8_object = class_file.add_constant(1, {
            let name = b"java/lang/Object";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let object_class = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_object.to_be_bytes());
            info
        });

        let utf8_init = class_file.add_constant(1, {
            let name = b"<init>";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let utf8_void_desc = class_file.add_constant(1, {
            let desc = b"()V";
            let mut info = Vec::new();
            info.extend_from_slice(&((desc.len() as u16).to_be_bytes()));
            info.extend_from_slice(desc);
            info
        });

        let name_and_type = class_file.add_constant(12, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_init.to_be_bytes());
            info.extend_from_slice(&utf8_void_desc.to_be_bytes());
            info
        });

        let utf8_code = class_file.add_constant(1, {
            let name = b"Code";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        class_file.access_flags = 0x0021;
        class_file.this_class = class_info;
        class_file.super_class = object_class;

        let mut builder = BytecodeBuilder::new();
        builder.emit_u8(opcodes::ALOAD_0);
        builder.emit_u8(opcodes::INVOKESPECIAL);
        builder.emit_u16(name_and_type);
        builder.emit_u8(opcodes::RETURN);

        let code_bytes = builder.get_bytes();
        let code_attr_length = 12 + code_bytes.len();

        let constructor = MethodInfo {
            access_flags: 0x0001,
            name_index: utf8_init,
            descriptor_index: utf8_void_desc,
            attributes_count: 1,
            attributes: vec![AttributeInfo {
                attribute_name_index: utf8_code,
                info: {
                    let mut info = Vec::new();
                    info.extend_from_slice(&((code_attr_length as u32).to_be_bytes()));
                    info.extend_from_slice(&(1u16).to_be_bytes());
                    info.extend_from_slice(&(1u16).to_be_bytes());
                    info.extend_from_slice(&((code_bytes.len() as u32).to_be_bytes()));
                    info.extend_from_slice(&code_bytes);
                    info.extend_from_slice(&(0u16).to_be_bytes());
                    info.extend_from_slice(&(0u16).to_be_bytes());
                    info
                },
            }],
        };

        class_file.add_method(constructor);
        class_file.constant_pool_count = class_file.constant_pool.len() as u16 + 1;

        let test_path = "test/MethodTest.class";
        write_bytecode(&class_file, test_path)?;

        Ok(())
    }

    #[test]
    fn test_basic_program() -> io::Result<()> {
        let mut class_file = ClassFile::new();

        // 1. class name and Object class
        let utf8_main_class = class_file.add_constant(1, {
            let name = b"MainTest";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let main_class = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_main_class.to_be_bytes());
            info
        });

        let utf8_object = class_file.add_constant(1, {
            let name = b"java/lang/Object";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let object_class = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_object.to_be_bytes());
            info
        });

        // 2. System.out reference
        let utf8_system = class_file.add_constant(1, {
            let name = b"java/lang/System";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let system_class = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_system.to_be_bytes());
            info
        });

        let utf8_out = class_file.add_constant(1, {
            let name = b"out";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let utf8_printstream = class_file.add_constant(1, {
            let name = b"Ljava/io/PrintStream;";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let out_field = class_file.add_constant(12, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_out.to_be_bytes());
            info.extend_from_slice(&utf8_printstream.to_be_bytes());
            info
        });

        let out_ref = class_file.add_constant(9, {
            let mut info = Vec::new();
            info.extend_from_slice(&system_class.to_be_bytes());
            info.extend_from_slice(&out_field.to_be_bytes());
            info
        });

        // 3. println method reference
        let utf8_println = class_file.add_constant(1, {
            let name = b"println";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let utf8_println_desc = class_file.add_constant(1, {
            let desc = b"(Ljava/lang/String;)V";
            let mut info = Vec::new();
            info.extend_from_slice(&((desc.len() as u16).to_be_bytes()));
            info.extend_from_slice(desc);
            info
        });

        let println_method = class_file.add_constant(12, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_println.to_be_bytes());
            info.extend_from_slice(&utf8_println_desc.to_be_bytes());
            info
        });

        let utf8_printstream_class = class_file.add_constant(1, {
            let name = b"java/io/PrintStream";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let printstream_class = class_file.add_constant(7, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_printstream_class.to_be_bytes());
            info
        });

        let println_ref = class_file.add_constant(10, {
            let mut info = Vec::new();
            info.extend_from_slice(&printstream_class.to_be_bytes());
            info.extend_from_slice(&println_method.to_be_bytes());
            info
        });

        // 4. "Hello, world!" string constant
        let utf8_hello = class_file.add_constant(1, {
            let text = b"Hello, world!";
            let mut info = Vec::new();
            info.extend_from_slice(&((text.len() as u16).to_be_bytes()));
            info.extend_from_slice(text);
            info
        });

        let string_ref = class_file.add_constant(8, {
            let mut info = Vec::new();
            info.extend_from_slice(&utf8_hello.to_be_bytes());
            info
        });

        // 5. main method
        let utf8_main = class_file.add_constant(1, {
            let name = b"main";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        let utf8_main_desc = class_file.add_constant(1, {
            let desc = b"([Ljava/lang/String;)V";
            let mut info = Vec::new();
            info.extend_from_slice(&((desc.len() as u16).to_be_bytes()));
            info.extend_from_slice(desc);
            info
        });

        // 6. code attribute
        let utf8_code = class_file.add_constant(1, {
            let name = b"Code";
            let mut info = Vec::new();
            info.extend_from_slice(&((name.len() as u16).to_be_bytes()));
            info.extend_from_slice(name);
            info
        });

        // class properties
        class_file.access_flags = 0x0021; // PUBLIC | SUPER
        class_file.this_class = main_class;
        class_file.super_class = object_class;

        /* main method bytecode */
        let mut builder = BytecodeBuilder::new();
        builder.emit_u8(opcodes::GETSTATIC);
        builder.emit_u16(out_ref);
        builder.emit_u8(opcodes::LDC);
        builder.emit_u8(string_ref as u8);
        builder.emit_u8(opcodes::INVOKEVIRTUAL);
        builder.emit_u16(println_ref);
        builder.emit_u8(opcodes::RETURN);

        let code_bytes = builder.get_bytes();
        let code_attr_length = 12 + code_bytes.len();

        let main_method = MethodInfo {
            access_flags: 0x0009, // PUBLIC | STATIC
            name_index: utf8_main,
            descriptor_index: utf8_main_desc,
            attributes_count: 1,
            attributes: vec![AttributeInfo {
                attribute_name_index: utf8_code,
                info: {
                    let mut info = Vec::new();
                    info.extend_from_slice(&((code_attr_length as u32).to_be_bytes()));
                    info.extend_from_slice(&(2u16).to_be_bytes()); // max_stack - increased to 2
                    info.extend_from_slice(&(1u16).to_be_bytes()); // max_locals - set to 1 for args array
                    info.extend_from_slice(&((code_bytes.len() as u32).to_be_bytes()));
                    info.extend_from_slice(&code_bytes);
                    info.extend_from_slice(&(0u16).to_be_bytes()); // exception_table_length
                    info.extend_from_slice(&(0u16).to_be_bytes()); // attributes_count
                    info
                },
            }],
        };

        class_file.add_method(main_method);
        class_file.constant_pool_count = class_file.constant_pool.len() as u16 + 1;

        write_bytecode(&class_file, "test/MainTest.class")?;

        Ok(())
    }
}
