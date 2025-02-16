from ropper import RopperService
import find_magic_gadget
import sys
# 初始化 RopperService
service = RopperService()

def usage():
    print("Usage: python finder.py [binary_path]")
    print("  binary_path: Optional. Path to the binary file. If not provided, defaults to '/lib/x86_64-linux-gnu/libc.so.6'.")

# 加载目标文件
def get_binary_path():
    # 检查命令行参数是否传入路径，如果没有则使用默认路径
    if len(sys.argv) > 1:
        return sys.argv[1]  # 获取第一个命令行参数
    else:
        return "/lib/x86_64-linux-gnu/libc.so.6"  # 默认路径
binary_path = get_binary_path()  # 替换为目标文件路径
service.addFile(binary_path)

# # 搜索 gadgets
service.loadGadgetsFor()
# files = service.files

for file, gadget in service.search(search='mov rdx%call'):
    if 'syscall' in gadget.simpleInstructionString():
        continue
    # print(gadget)
    find_magic_gadget.Globals.assembly = gadget.simpleInstructionString()
    find_magic_gadget.emulaterun([0,0x8,0x10,0x18,0x20,0x28,0xa0,0xc0,0xd8,0xe0,0x1c0,0x268]) # 不可写的地址
    if(find_magic_gadget.Globals.check()):
        print(gadget)