use std::io;

fn main() {
    let mut buf = String::new();
    let stdin = io::stdin();
    loop {
        buf.clear();
        let len = stdin.read_line(&mut buf).unwrap();
        let input = &buf[..len].trim();
        if input.starts_with("0x") {
            let hex = &input[2..];
            if hex.len() > 8 {
                println!("Hex input too long");
                continue;
            }
            let value = if let Ok(val) = u64::from_str_radix(&hex, 16) {
                val
            } else {
                println!("Parse int error!");
                continue
            };
            parse_xthead_insn(value);
        } else if input == &"q" {
            break
        }
    }
}

const OPCODE_CUSTOM0: u8  = 0b000_1011;
const OPCODE_SYSTEM: u8   = 0b111_0011;

const FUNCT3_CUSTOM0_SYNC:  u8 = 0b000;
const FUNCT3_CUSTOM0_ALU:   u8 = 0b001;
const FUNCT3_CUSTOM0_EXT:   u8 = 0b010;
const FUNCT3_CUSTOM0_EXTU:  u8 = 0b011;
const FUNCT3_CUSTOM0_XREG_LOAD:  u8 = 0b100;
const FUNCT3_CUSTOM0_XREG_STORE: u8 = 0b101;
const FUNCT3_CUSTOM0_FREG_LOAD:  u8 = 0b110;
const FUNCT3_CUSTOM0_FREG_STORE: u8 = 0b111;

const FUNCT12_SYNC_DCACHE_CALL: u16 = 0x001;
const FUNCT12_SYNC_DCACHE_IALL: u16 = 0x002;
const FUNCT12_SYNC_DCACHE_CIALL: u16 = 0x003;
const FUNCT12_SYNC_IPUSH: u16 = 0x004;
const FUNCT12_SYNC_IPOP: u16 = 0x005;
const FUNCT12_SYNC_ICACHE_IALL: u16 = 0x006;
const FUNCT12_SYNC_ICACHE_IALLS: u16 = 0x011;
const FUNCT12_SYNC_L2CACHE_CALL: u16 = 0x015;
const FUNCT12_SYNC_L2CACHE_IALL: u16 = 0x016;
const FUNCT12_SYNC_L2CACHE_CIALL: u16 = 0x017;
const FUNCT12_SYNC_SYNC: u16 = 0x018;
const FUNCT12_SYNC_SYNC_S: u16 = 0x019;
const FUNCT12_SYNC_SYNC_I: u16 = 0x01A;
const FUNCT12_SYNC_SYNC_IS: u16 = 0x01B;
const FUNCT12_SYNC_DCACHE_CSW: u16 = 0x021;
const FUNCT12_SYNC_DCACHE_ISW: u16 = 0x022;
const FUNCT12_SYNC_DCACHE_CISW: u16 = 0x023;
const FUNCT12_SYNC_DCACHE_CVAL1: u16 = 0x024;
const FUNCT12_SYNC_DCACHE_CVA: u16 = 0x025;
const FUNCT12_SYNC_DCACHE_IVA: u16 = 0x026;
const FUNCT12_SYNC_DCACHE_CIVA: u16 = 0x027;
const FUNCT12_SYNC_DCACHE_CPAL1: u16 = 0x028;
const FUNCT12_SYNC_DCACHE_CPA: u16 = 0x029;
const FUNCT12_SYNC_DCACHE_IPA: u16 = 0x02A;
const FUNCT12_SYNC_DCACHE_CIPA: u16 = 0x02B;
const FUNCT12_SYNC_ICACHE_IVA: u16 = 0x030;
const FUNCT12_SYNC_ICACHE_IPA: u16 = 0x038;

const FUNCT5_ALU_ADDSL: u8 = 0b0_0000;
const FUNCT7_ALU_MULA:  u8 = 0b001_0000;
const FUNCT7_ALU_MULAH: u8 = 0b001_0100;
const FUNCT7_ALU_MULAW: u8 = 0b001_0010;
const FUNCT7_ALU_MULS:  u8 = 0b001_0001;
const FUNCT7_ALU_MULSH: u8 = 0b001_0101;
const FUNCT7_ALU_MULSW: u8 = 0b001_0011;
const FUNCT7_ALU_MVEQZ: u8 = 0b010_0000;
const FUNCT7_ALU_MVNEZ: u8 = 0b010_0001;
const FUNCT6_ALU_SRRI:  u8 = 0b00_0100;
const FUNCT7_ALU_SRRIW: u8 = 0b000_1010;
const FUNCT12_ALU_FF0:    u16 = 0b1000_0100_0000;
const FUNCT12_ALU_FF1:    u16 = 0b1000_0110_0000;
const FUNCT12_ALU_REV:    u16 = 0b1000_0010_0000;
const FUNCT12_ALU_REVW:   u16 = 0b1001_0000_0000;
const FUNCT6_ALU_TST:      u8 = 0b10_0010;
const FUNCT12_ALU_TSTNBZ: u16 = 0b1000_0000_0000;

const FUNCT3_SYSTEM_CSRRW: u8 = 0b001;
const FUNCT3_SYSTEM_CSRRS: u8 = 0b010;
const FUNCT3_SYSTEM_CSRRC: u8 = 0b011;
const FUNCT3_SYSTEM_CSRRWI: u8 = 0b101;
const FUNCT3_SYSTEM_CSRRSI: u8 = 0b110;
const FUNCT3_SYSTEM_CSRRCI: u8 = 0b111;

fn parse_xthead_insn(ins: u64) {
    let rd = translate_abi_name(((ins >> 7) & 0b1_1111) as u8);
    let rs1 = translate_abi_name(((ins >> 15) & 0b1_1111) as u8);
    let rs2 = translate_abi_name(((ins >> 20) & 0b1_1111) as u8);
    let imm5 = (ins >> 20) & 0b1_1111;
    let imm2 = (ins >> 25) & 0b11;
    let imm6 = (ins >> 20) & 0b11_1111;
    let imm6_2 = (ins >> 26) & 0b11_1111;
    let opcode = (ins & 0b111_1111) as u8;
    let funct3 = ((ins >> 12) & 0b111) as u8;
    let funct7 = ((ins >> 25) & 0b111_1111) as u8;
    let funct5 = ((ins >> 27) & 0b1_1111) as u8;
    let funct6 = ((ins >> 26) & 0b11_1111) as u8;
    let funct12 = ((ins >> 20) & 0b1111_1111_1111) as u16;
    let csr = ((ins >> 20) & 0xFFF) as u16;
    let uimm_csr = ((ins >> 15) & 0b11111) as u16;
    match (opcode, funct3) {
        (OPCODE_CUSTOM0, FUNCT3_CUSTOM0_SYNC) => match funct12 { // (funct12, rd)
            FUNCT12_SYNC_DCACHE_CALL => println!("dcache.call"),
            FUNCT12_SYNC_DCACHE_IALL => println!("dcache.iall"),
            FUNCT12_SYNC_DCACHE_CIALL => println!("dcache.ciall"),
            FUNCT12_SYNC_IPUSH => println!("ipush"),
            FUNCT12_SYNC_IPOP => println!("ipop"),
            FUNCT12_SYNC_ICACHE_IALL => println!("icache.iall"),
            FUNCT12_SYNC_ICACHE_IALLS => println!("icache.ialls"),
            FUNCT12_SYNC_L2CACHE_CALL => println!("l2cache.call"),
            FUNCT12_SYNC_L2CACHE_IALL => println!("l2cache.iall"),
            FUNCT12_SYNC_L2CACHE_CIALL => println!("l2cache.ciall"),
            FUNCT12_SYNC_SYNC => println!("sync"),
            FUNCT12_SYNC_SYNC_S => println!("sync.s"),
            FUNCT12_SYNC_SYNC_I => println!("sync.i"),
            FUNCT12_SYNC_SYNC_IS => println!("sync.is"),
            FUNCT12_SYNC_DCACHE_CSW => println!("dcache.csw {}", rs1),
            FUNCT12_SYNC_DCACHE_ISW => println!("dcache.isw {}", rs1),
            FUNCT12_SYNC_DCACHE_CISW => println!("dcache.cisw {}", rs1),
            FUNCT12_SYNC_DCACHE_CVAL1 => println!("dcache.cval1 {}", rs1),
            FUNCT12_SYNC_DCACHE_CVA => println!("dcache.cva {}", rs1),
            FUNCT12_SYNC_DCACHE_IVA => println!("dcache.iva {}", rs1),
            FUNCT12_SYNC_DCACHE_CIVA => println!("dcache.civa {}", rs1),
            FUNCT12_SYNC_DCACHE_CPAL1 => println!("dcache.cpal1 {}", rs1),
            FUNCT12_SYNC_DCACHE_CPA => println!("dcache.cpa {}", rs1),
            FUNCT12_SYNC_DCACHE_IPA => println!("dcache.ipa {}", rs1),
            FUNCT12_SYNC_DCACHE_CIPA => println!("dcache.cipa {}", rs1),
            FUNCT12_SYNC_ICACHE_IVA => println!("icache.iva {}", rs1),
            FUNCT12_SYNC_ICACHE_IPA => println!("icache.ipa {}", rs1),
            _ => println!("custom0 sync {:x}", ins),
        },
        (OPCODE_CUSTOM0, FUNCT3_CUSTOM0_ALU) => match funct7 {
            FUNCT7_ALU_MULA =>  println!("mula {}, {}, {}", rd, rs1, rs2),
            FUNCT7_ALU_MULAH => println!("mulah {}, {}, {}", rd, rs1, rs2),
            FUNCT7_ALU_MULAW => println!("mulaw {}, {}, {}", rd, rs1, rs2),
            FUNCT7_ALU_MULS =>  println!("muls {}, {}, {}", rd, rs1, rs2),
            FUNCT7_ALU_MULSH => println!("mulsh {}, {}, {}", rd, rs1, rs2),
            FUNCT7_ALU_MULSW => println!("mulsw {}, {}, {}", rd, rs1, rs2),
            FUNCT7_ALU_MVEQZ => println!("mveqz {}, {}, {}", rd, rs1, rs2),
            FUNCT7_ALU_MVNEZ => println!("mvnez {}, {}, {}", rd, rs1, rs2),
            FUNCT7_ALU_SRRIW => println!("srriw {}, {}, {}", rd, rs1, imm5),
            _ if funct5 == FUNCT5_ALU_ADDSL => 
                println!("addsl {}, {}, {}, {}", rd, rs1, rs2, imm2),
            _ if funct6 == FUNCT6_ALU_SRRI => 
                println!("srri {}, {}, {}", rd, rs1, imm6),
            _ if funct6 == FUNCT6_ALU_TST =>
                println!("tst {}, {}, {}", rd, rs1, imm6),
            _ => match funct12 {
                FUNCT12_ALU_FF0 => println!("ff0 {}, {}", rd, rs1),
                FUNCT12_ALU_FF1 => println!("ff1 {}, {}", rd, rs1),
                FUNCT12_ALU_REV => println!("rev {}, {}", rd, rs1),
                FUNCT12_ALU_REVW => println!("revw {}, {}", rd, rs1),
                FUNCT12_ALU_TSTNBZ => println!("tstnbz {}, {}", rd, rs1),
                _ => println!("custom0 alu {:x}", ins),
            }
        },
        (OPCODE_CUSTOM0, FUNCT3_CUSTOM0_EXT) =>
            println!("ext {}, {}, {}, {}", rd, rs1, imm6_2, imm6),
        (OPCODE_CUSTOM0, FUNCT3_CUSTOM0_EXTU) =>
            println!("extu {}, {}, {}, {}", rd, rs1, imm6_2, imm6),
        (OPCODE_SYSTEM, FUNCT3_SYSTEM_CSRRW) =>
            println!("csrrw {}, {:#x}, {}", rd, csr, rs1),
        (OPCODE_SYSTEM, FUNCT3_SYSTEM_CSRRS) =>
            println!("csrrs {}, {:#x}, {}", rd, csr, rs1),
        (OPCODE_SYSTEM, FUNCT3_SYSTEM_CSRRC) =>
            println!("csrrc {}, {:#x}, {}", rd, csr, rs1),
        (OPCODE_SYSTEM, FUNCT3_SYSTEM_CSRRWI) =>
            println!("csrrwi {}, {:#x}, {}", rd, csr, uimm_csr),
        (OPCODE_SYSTEM, FUNCT3_SYSTEM_CSRRSI) =>
            println!("csrrsi {}, {:#x}, {}", rd, csr, uimm_csr),
        (OPCODE_SYSTEM, FUNCT3_SYSTEM_CSRRCI) =>
            println!("csrrci {}, {:#x}, {}", rd, csr, uimm_csr),
        _ => println!("others, opcode {:#x}, funct3 {:#x}", opcode, funct3),
    }
}

fn translate_abi_name(idx: u8) -> &'static str {
    assert!(idx < 32);
    const ABI_NAME: [&'static str; 32] = [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
        "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
        "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
        "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
    ];
    ABI_NAME[idx as usize]
}
