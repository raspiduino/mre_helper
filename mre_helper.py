# Script file for helping with RE MRE VXP files in IDA
# By giangvinhloc610

import idautils
import ida_funcs
import idc

# Global variables
api_addr = {} # Detected APIs and their address

# Helper functions

# Rename helper function to rename event handler functions
# func: address / name of the handler register function
# opt: if opt != 0 -> different way to pass address
# name: new name of the event handler function
def rename_handler(func, name):
    addr = 0
    if isinstance(func, str):
        # func passed as a string of function name -> get function ref address
        addr = next(XrefsTo(api_addr[func])).frm
    else:
        # func passed as int of function ref address -> use it directly
        addr = func

    while True:
        addr -= 4
        ins = GetDisasm(addr).split(" ")
        if ins[0] == "LDR":
            # Found it, its current name is ins[-3][2:], which will be something like 'sub_8276C'
            # So we rename it
            idc.set_name(int(ins[-3][2:].split("sub_")[-1], 16), name)
            break

# Rename APIs

# Loop through each strings in the name list
# See if it starts with "aVm" (the beginning of name for API string)
for ea, name in idautils.Names():
    if "aVm" == name[:3]:
        # It's the name of API string
        # Get the first cross reference to it
        # In many cases there are 3 cross reference to the string
        # 2 first one is 2 instructions to load the string
        # The last one is the data reference

        for ref in idautils.XrefsTo(ea):
            # Get the first element
            # And find the function name
            # And rename the function
            try:
                start_ea = ida_funcs.get_func(ref.frm).start_ea
                name = idc.get_strlit_contents(ea).decode("utf-8")
                idc.set_name(start_ea, name)

                # Add the detected API's address
                api_addr[name] = start_ea
            except Exception as e:
                break

            # Then break out of the loop
            break

# Rename main function
vm_reg_sysevt_callback_ref_addr = 0
try:
    vm_reg_sysevt_callback_ref_addr = next(XrefsTo(api_addr["vm_reg_sysevt_callback"])).frm
    idc.set_name(ida_funcs.get_func(vm_reg_sysevt_callback_ref_addr).start_ea, "vm_main")
except Exception as e:
    print(e)

# Rename event handlers
try:
    rename_handler(vm_reg_sysevt_callback_ref_addr, "handle_sysevt")
    rename_handler("vm_reg_keyboard_callback", "handle_keyevt")
    rename_handler("vm_reg_pen_callback", "handle_penevt")
    rename_handler("vm_reg_msg_proc", "handle_message")
except Exception as e:
    pass
