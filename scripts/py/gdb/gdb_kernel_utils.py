#    This file is part of the vkdbg distribution (https://github.com/Group-IB/vkdbg).
#    Copyright (C) 2021 Timur Chernykh
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

import gdb.printing
import gdb
import re
import subprocess
import os

char_type: None
char_pointer_type: None

uintptr_type: None
uintptr_pointer_type: None

list_type: None
list_pointer_type: None

module_type: None
module_pointer_type: None

module_sect_attrs_type: None
module_sect_attrs_pointer_type: None

module_sect_attr_type: None
module_sect_attr_pointer_type: None

uint_type: None
uint_pointer_type: None

modules_entry: None

types_loaded = False
kernel_attached = False
attached_module_objects = []


def check_ready() -> bool:
    global kernel_attached
    global types_loaded

    if not kernel_attached:
        error("Attach kernel firstly")
        return False

    if not types_loaded:
        error("Not all types loaded, load it firstly")
        return False

    return True


def error(msg: str) -> None:
    gdb.write(f"[!] {msg}\n")


def message(msg: str) -> None:
    gdb.write(f"[*] {msg}\n")


def load_types():
    global char_type
    global char_pointer_type
    global uintptr_type
    global uintptr_pointer_type
    global list_type
    global list_pointer_type
    global module_type
    global module_pointer_type
    global modules_entry
    global types_loaded
    global module_sect_attrs_type
    global module_sect_attrs_pointer_type
    global module_sect_attr_type
    global module_sect_attr_pointer_type
    global uint_type
    global uint_pointer_type

    try:
        char_type = gdb.lookup_type('char')
        char_pointer_type = char_type.pointer()

        uintptr_type = gdb.lookup_type('uintptr_t')
        uintptr_pointer_type = uintptr_type.pointer()

        list_type = gdb.lookup_type('struct list_head')
        list_pointer_type = list_type.pointer()

        module_type = gdb.lookup_type('struct module')
        module_pointer_type = module_type.pointer()

        module_sect_attrs_type = gdb.lookup_type('struct module_sect_attrs')
        module_sect_attrs_pointer_type = module_sect_attrs_type.pointer()

        module_sect_attr_type = gdb.lookup_type('struct module_sect_attr')
        module_sect_attr_pointer_type = module_sect_attr_type.pointer()

        uint_type = gdb.lookup_type('unsigned int')
        uint_pointer_type = uint_type.pointer()

        modules_entry = gdb.lookup_symbol("modules")

    except Exception as e:
        error("Couldn't load all types. Please, (re)attach kernel or connect to remote VM and (re)attach kernel to "
              "load it")
        return

    message("All kernel types loaded successfully")
    types_loaded = True


load_types()


def get_current_kallsyms_file():
    return os.getenv('VKDBG_CURRENT_KALLSYMS')


def get_current_kernel_image():
    return os.getenv('VKDBG_CURRENT_KERNEL')


def get_module_objects_dir():
    return os.getenv('VKDBG_MODULE_OBJECTS_DIR')


def get_assumed_module_object(module_name: str):
    module_objects_dir = get_module_objects_dir()
    if module_objects_dir is None:
        return None

    for obj_file in os.listdir(module_objects_dir):
        if obj_file.endswith(".ko") and module_name in obj_file:
            return os.path.join(module_objects_dir, obj_file)

    return None


def get_object_stext_address(kernel_image):
    objdump = subprocess.Popen(["objdump", "-t", kernel_image], stdout=subprocess.PIPE)
    for line in objdump.stdout.readlines():
        sym = line.decode('utf-8')
        if '_stext' in sym:
            stext_addr = re.findall(r'[0-9a-fA-F]*', sym)[0]
            message(f"Found object stext addr {stext_addr}")
            return int(stext_addr, 16)


def get_kernel_base_address(kallsyms_file_path):
    message(f'Reading {kallsyms_file_path}...')
    kallsyms = open(kallsyms_file_path, 'r')
    syms = kallsyms.readlines()
    for sym in syms:
        if '_stext' in sym:
            stext_addr = re.findall(r'[0-9a-fA-F]*', sym)[0]
            message(f"Found kernel stext addr {stext_addr}")
            return int(stext_addr, 16)


def value_has_field(gdb_value, field: str):
    for f in gdb_value.type.fields():
        if field == f.name:
            return True
    return False


class GetKernelObjectStextAdress(gdb.Command):
    cmd = 'get-kernel-object-stext-address'

    def __init__(self):
        super(GetKernelObjectStextAdress, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if (len(argv) < 1):
            message(f"Please, specify path to kernel image or use 'current'")
            message(f"Examples: {self.cmd} ~/kernel-debug/current/meta/kallsyms")
            message(f"          {self.cmd} current")
            return

        kernel_image = argv[0]
        if kernel_image == 'current':
            kernel_image = get_current_kernel_image()

        addr = get_object_stext_address(kernel_image)
        message(f"{str(addr)}")
        return addr


class GetKernelBaseAddress(gdb.Command):
    cmd = "get-kernel-base-addres"

    def __init__(self):
        super(GetKernelBaseAddress, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if (len(argv) < 1):
            message(f"Please, specify path to kallsyms file or use 'current'")
            message(f"Examples: {self.cmd} ~/kernel-debug/current/meta/kallsyms")
            message(f"          {self.cmd} current")
            return

        kallsyms_file_path = argv[0]

        if kallsyms_file_path == "current":
            kallsyms_file_path = get_current_kallsyms_file()

        addr = get_kernel_base_address(kallsyms_file_path)
        message(f"{str(addr)}")
        return addr


get_kernel_object_stext_address_cmd = GetKernelObjectStextAdress()
get_kernel_base_address_cmd = GetKernelBaseAddress()


class AttachKernel(gdb.Command):
    cmd = 'attach-kernel'

    def __init__(self):
        super(AttachKernel, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        kallsyms_file = ''
        kernel_image = ''

        if len(argv) > 0:
            if [argv[0]] == 'help':
                message(f"Usage {self.cmd} [kallsyms_file] [kernel_image]'")
                return
            kallsyms_file = argv[0]
        else:
            kallsyms_file = get_current_kallsyms_file()

        if len(argv) > 1:
            kernel_image = argv[0]
        else:
            kernel_image = get_current_kernel_image()

        try:
            object_stext_address = get_object_stext_address(kernel_image)
            if object_stext_address is None:
                raise Exception("Couldn't find stext address in object")

            kernel_base_address = get_kernel_base_address(kallsyms_file)
            if object_stext_address is None:
                raise Exception("Couldn't find stext address in running kernel (kallsyms)")

            offset = kernel_base_address - object_stext_address

        except Exception as e:
            error(f"Error while calculating offset: {str(e)}")
            return

        message(f"Calculated offset: hex {str(hex(offset))}, dec {offset}")
        set_exec_cmd = f"exec-file {get_current_kernel_image()}"
        load_symbols_cmd = f"add-symbol-file {kernel_image} -o {hex(offset)}"
        gdb.execute(set_exec_cmd)
        gdb.execute(load_symbols_cmd)
        global kernel_attached
        load_types()
        kernel_attached = True


class DetachKernel(gdb.Command):
    cmd = 'detach-kernel'

    def __init__(self):
        super(DetachKernel, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global kernel_attached
        gdb.execute(f"delete")
        gdb.execute(f"exec-file")
        gdb.execute(f"symbol-file")
        gdb.execute(f"dir")
        kernel_attached = False


attach_kernel_cmd = AttachKernel()
detach_kernel_cmd = DetachKernel()


class Module:
    def __init__(self):
        self.name = ""
        self.text = 0
        self.data = 0
        self.bss = 0
        self.symtab = 0
        self.address = 0


def get_pure_string_from_gdb_ptr(char_ptr) -> str:
    splt = str(char_ptr).split(" ")
    if len(splt) > 1:
        return splt[1].replace('"', '')
    return str(char_ptr)


def fill_sections(module: Module, raw_module):
    try:
        module_attrs = raw_module['sect_attrs'].cast(module_sect_attrs_pointer_type).dereference()
        nsection = int(module_attrs['nsections'].cast(uint_type))
        for offset in range(nsection):
            section = (module_attrs["attrs"].cast(module_sect_attr_pointer_type) + offset).dereference()

            name = ""
            if value_has_field(section, "name"):
                name = get_pure_string_from_gdb_ptr(section['name'].cast(char_pointer_type))
            elif value_has_field(section, "battr"):
                name = get_pure_string_from_gdb_ptr(section['battr']["attr"]["name"].cast(char_pointer_type))

            address = section['address'].cast(uintptr_type)
            if name == '.text':
                module.text = hex(int(address))
            elif name == '.bss':
                module.bss = hex(int(address))
            elif name == '.data':
                module.data = hex(int(address))
            elif name == '.symtab':
                module.symtab = hex(int(address))

    except Exception as e:
        error(str(e))


def get_all_modules():
    if not modules_entry[0]:
        message("Error: couldn't find 'modules' symbol")
        return

    def first_entry(list_head):
        return list_head.cast(list_type).cast(list_pointer_type)

    def next_entry(entry_prt):
        return entry_prt.dereference()['next'].cast(list_pointer_type)

    def get_module_ptr(entry_ptr):
        return (entry_ptr.cast(uintptr_pointer_type) - 1).cast(module_pointer_type)

    def get_module(entry_ptr):
        return (entry_ptr.cast(uintptr_pointer_type) - 1).cast(module_pointer_type).dereference()

    def get_module_text(m):
        if value_has_field(m, 'module_core'):
            return m['module_core'].cast(uintptr_pointer_type)
        elif value_has_field(m, 'core_layout'):
            return m['core_layout']['base'].cast(uintptr_pointer_type)
        else:
            raise Exception("Unsupported kernel version")

    modules_head_ptr = first_entry(modules_entry[0].value())
    list_entry_ptr = next_entry(modules_head_ptr)

    all_modules = []
    module = Module()
    raw_module = get_module(modules_head_ptr)

    module.name = get_pure_string_from_gdb_ptr(raw_module['name'].cast(char_pointer_type))
    module.text = get_module_text(raw_module)
    module.address = get_module_ptr(modules_head_ptr)
    fill_sections(module, raw_module)
    all_modules.append(module)

    while modules_head_ptr != list_entry_ptr:
        module = Module()

        raw_module = get_module(list_entry_ptr)
        module.name = get_pure_string_from_gdb_ptr(raw_module['name'].cast(char_pointer_type))
        module.text = get_module_text(raw_module)
        module.address = get_module_ptr(list_entry_ptr)
        fill_sections(module, raw_module)
        all_modules.append(module)
        list_entry_ptr = next_entry(list_entry_ptr)

    return all_modules


def find_module(module_name):
    modules = get_all_modules()
    found_module = None

    for module in modules:
        if module_name in str(module.name):
            found_module = module

    return found_module


def format_module(module) -> str:
    eval_expr = f"*(struct module*)({module.address.cast(uintptr_pointer_type)})"
    return gdb.parse_and_eval(eval_expr)


class ListKernelModules(gdb.Command):
    cmd = "list-kernel-modules"

    def __init__(self):
        super(ListKernelModules, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if not check_ready():
            return

        modules = get_all_modules()
        for module in modules:
            message(f'{module.text}: {module.name}')


class GetKernelModule(gdb.Command):
    cmd = "get-kernel-module"

    def __init__(self):
        super(GetKernelModule, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if not check_ready():
            return

        if len(argv) == 0:
            message(f"Usage {self.cmd} [module_name]'")
            return

        module_name = argv[0]

        try:
            found_module = find_module(module_name)
        except Exception as e:
            error(f"{e}")
            return

        if found_module is None:
            error(f"No such module found {module_name}")

        formatted = format_module(found_module)
        message(f"{formatted}")


get_kernel_module_cmd = GetKernelModule()
list_kernel_modules_cmd = ListKernelModules()


class LoadKernelModule(gdb.Command):
    cmd = 'load-kernel-module'

    def __init__(self):
        super(LoadKernelModule, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        global kernel_attached

        addr = ''
        if len(argv) == 0:
            message(f"Usage: '{self.cmd} <module_object> <addr> [src]'")
            return

        if len(argv) > 1:
            if argv[0] == 'help':
                message(f"Usage: '{self.cmd} <module_object> <addr>'")
                return
            else:
                module_object = argv[0]

            addr = argv[1]

        message(f"Read symbols from {module_object}, offset {addr}")
        gdb.execute(f"add-symbol-file {module_object} -o {addr}")


class AttachKernelModule(gdb.Command):
    cmd = 'attach-kernel-module'
    global attached_module_objects

    def __init__(self):
        super(AttachKernelModule, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        global kernel_attached
        if not check_ready():
            return

        if len(argv) == 0:
            message(f"Usage {self.cmd} <module_name> [module_object] [source_dir]'")
            return

        src_dir = os.getcwd()
        module_name = ""

        if len(argv) > 0:
            if [argv[0]] == 'help':
                message(f"Usage {self.cmd} <module_name> [module_object] [source_dir]'")
                return
            module_name = argv[0]

        if len(argv) > 1 and argv[1]:
            if os.path.isabs(argv[1]):
                module_object = argv[1]
            else:
                module_name = get_assumed_module_object(argv[1])
        else:
            message(f"Object for module {module_name} wasn't set explicitly, trying to assume...")
            module_object = get_assumed_module_object(module_name)
            if module_object is None:
                error("Cant find module object. You can use flag -m | --with-module to set up module debugging")
                error("Even if you'll attach module at kernel space that doesn't not mean it have debug symbols")
            else:
                module_object = module_object.replace('//', '/')

        if len(argv) > 2:
            src_dir = argv[2]

        found_module = find_module(module_name)

        if found_module is None:
            error(f"No such module found {module_name}")
            return

        message(f"Loading: {module_name}, offset: {found_module.address}")

        message(f"Reading symbols from: {module_object}")
        gdb.execute(f"add-symbol-file {module_object} {found_module.text} "
                    f"-s .bss {found_module.bss} "
                    f"-s .data {found_module.data} "
                    f"-s .symtab {found_module.symtab} ")

        attached_module_objects.append(module_object)
        message(f"Source dir: {src_dir}")
        gdb.execute(f"dir {src_dir}")


class DetachKernelModules(gdb.Command):
    cmd = 'detach-kernel-modules'
    global attached_module_objects

    def __init__(self):
        super(DetachKernelModules, self).__init__(self.cmd, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        global kernel_attached

        for module_object in attached_module_objects:
            message(f"removing {module_object}")
            gdb.execute(f"remove-symbol-file {module_object}")

        gdb.execute(f"delete")
        attached_module_objects.clear()


load_module_cmd = LoadKernelModule()
attach_module_cmd = AttachKernelModule()
detach_kernel_modules_cmd = DetachKernelModules()


def welcome():
    message(f'GIB kernel debug extension loaded!')
    message(f'Available commands:')
    message(f'  {attach_kernel_cmd.cmd} - load kernel symbols (see help to get more information)')
    message(f'  {attach_module_cmd.cmd} - load kernel module symbols (see help to get more information)')
    message(f'  {detach_kernel_cmd.cmd} - unload kernel symbols')
    message(f'  {detach_kernel_modules_cmd.cmd} - unload all kernel modules symbols')
    message(f'  {load_module_cmd.cmd} - load kernel module symbols even if kernel detached (see help to get more '
            f'information)')
    message(f'  {list_kernel_modules_cmd.cmd} - list all kernel modules')
    message(f'  {get_kernel_module_cmd.cmd} - get all info about kernel module')
    message(f'  {get_kernel_base_address_cmd.cmd}')
    message(f'  {get_kernel_object_stext_address_cmd.cmd}')
    message(f'You cat type help to any command to get know how to use it.')
    message(f'Happy kernel debugging!')


welcome()
