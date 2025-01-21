// Copyright (c) 2025 Elric Neumann. All rights reserved. MIT license.
use byteorder::{BigEndian, WriteBytesExt};
use std::fs::File;
use std::io::{self, Write};

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

// test a few for now, check later

pub mod opcodes {
    pub const ALOAD_0: u8 = 0x2a;
    pub const INVOKESPECIAL: u8 = 0xb7;
    pub const RETURN: u8 = 0xb1;
    pub const GETSTATIC: u8 = 0xb2;
    pub const LDC: u8 = 0x12;
    pub const INVOKEVIRTUAL: u8 = 0xb6;
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
}
