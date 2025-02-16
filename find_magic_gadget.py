from unicorn import Uc, UC_ARCH_X86, UC_MODE_64,  UC_HOOK_CODE
from unicorn.x86_const import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

class Globals:
    stopped = 0
    rdx = 0xffffffff
    call_addr = 0xffffffff
    assembly = ""
    @classmethod
    def init(cls):
        cls.stopped = 0
        cls.rdx = 0xffffffff
        cls.call_addr = 0xffffffff
        
    @classmethod
    def check(cls):
        if(cls.stopped == 0 and 0x2000000<= cls.rdx<= 0x2000500 and  0x2000000<= cls.call_addr <= 0x2000500 ):
            return True
        else:
            return False
    
    
    
    
def emulaterun(offsets=None):
    Globals.init()
    REGISTER_MAP = {
        0: UC_X86_REG_RAX,
        1: UC_X86_REG_RCX,
        2: UC_X86_REG_RDX,
        3: UC_X86_REG_RBX,
        4: UC_X86_REG_RSP,
        5: UC_X86_REG_RBP,
        6: UC_X86_REG_RSI,
        7: UC_X86_REG_RDI,
        8: UC_X86_REG_R8,
        9: UC_X86_REG_R9,
        10: UC_X86_REG_R10,
        11: UC_X86_REG_R11,
        12: UC_X86_REG_R12,
        13: UC_X86_REG_R13,
        14: UC_X86_REG_R14,
        15: UC_X86_REG_R15,
    }
    def hook_code(mu, address, size, user_data):
        # 读取当前指令
        code = mu.mem_read(address, size)
        rip = mu.reg_read(UC_X86_REG_RIP)

        # 检测指令类型
        if code[0] == 0xE8:  # CALL rel32 (RIP 相对寻址)
            # 解析目标地址
            offset = int.from_bytes(code[1:], byteorder="little", signed=True)
            target = rip + size + offset
            # print(f"[+] Detected CALL rel32 at {rip:#x}, target address: {target:#x}")
            Globals.call_addr = target
            mu.reg_write(UC_X86_REG_RIP, address + size)  # 跳过当前指令
            
        elif code[0] in (0xFF,):  # CALL r/m64
            modrm = code[1]  # ModR/M 字节
            mod = (modrm >> 6) & 0x3  # Mod 字段
            reg = (modrm >> 3) & 0x7  # Reg 字段
            rm = modrm & 0x7  # R/M 字段

            if reg == 2:  # CALL r/m64 的 opcode 是 FF /2
                # 解析寄存器或内存地址作为目标
                if mod == 0:  # 无偏移的寄存器/内存寻址
                    target = mu.reg_read(REGISTER_MAP[rm])  # rax, rcx, rdx, ...
                elif mod == 1:  # 带 1 字节偏移量的内存寻址
                    disp = int.from_bytes(code[2:3], byteorder="little", signed=True)
                    base = mu.reg_read(REGISTER_MAP[rm])
                    target = base + disp
                elif mod == 2:  # 带 4 字节偏移量的内存寻址
                    disp = int.from_bytes(code[2:6], byteorder="little", signed=True)
                    base = mu.reg_read(REGISTER_MAP[rm])
                    target = base + disp
                else:  # mod == 3，直接调用寄存器
                    target = mu.reg_read(REGISTER_MAP[rm])
                
                # print(f"[+] Detected CALL r/m64 at {rip:#x}, target address: {target:#x}")
                Globals.call_addr = target
                mu.reg_write(UC_X86_REG_RIP, address + size)  # 跳过当前指令
        else:
            pass  # 忽略其他指令

            
    # Keystone: 转换汇编为机器码
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    assembly = Globals.assembly
    encoding, _ = ks.asm(assembly)
    hlt_instruction, _ = ks.asm("hlt")
    machine_code = bytes(encoding) + bytes(hlt_instruction)

    # 打印机器码
    # print(f"Machine Code: {machine_code.hex()}")

    # Unicorn: 创建模拟器
    emu = Uc(UC_ARCH_X86, UC_MODE_64)

    # 定义内存布局
    ADDRESS = 0x1000000
    SIZE = 2 * 1024 * 1024
    STACK_ADDR = 0x2000000
    STACK_SIZE = 0x10000

    emu.mem_map(ADDRESS, SIZE)
    emu.mem_map(STACK_ADDR, STACK_SIZE)

    # 初始化栈指针
    emu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 8)

    # 填充栈帧内容为指向自身的指针
    for offset in range(0, STACK_SIZE, 8):  # 每 8 字节为一个指针
        addr = STACK_ADDR + offset
        emu.mem_write(addr, addr.to_bytes(8, 'little'))
        
    if offsets:
        for offset in offsets:
            addr = STACK_ADDR + offset
            emu.mem_write(addr, b"aaaaaaaa")  
            
    
    # 写入机器码
    emu.mem_write(ADDRESS, machine_code)

    # 初始化寄存器
    rax_value = 0x2000200
    emu.reg_write(UC_X86_REG_RAX, rax_value)

    rbx_value = 0x2000000
    emu.reg_write(UC_X86_REG_RBX, rbx_value)

    rdi_value = 0x2000000
    emu.reg_write(UC_X86_REG_RDX, rdi_value)

    rdx_value = 0x421
    emu.reg_write(UC_X86_REG_RDX, rdx_value)

    # 添加 Hook
    emu.hook_add(UC_HOOK_CODE, hook_code)

    # 执行代码
    try:
        emu.emu_start(ADDRESS, ADDRESS + len(machine_code))
    except Exception as e:
        # print(f"Execution stopped: {e}")
        Globals.stopped = 1

    # 查看寄存器结果
    # rax = emu.reg_read(UC_X86_REG_RAX)
    rdx = emu.reg_read(UC_X86_REG_RDX)
    # rdi = emu.reg_read(UC_X86_REG_RDI)

    # print(f"RAX = {hex(rax)}")
    # print(f"RDX = {hex(rdx)}")
    # print(f"RDI = {hex(rdi)}")
    Globals.rdx = rdx
    