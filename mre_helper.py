# Script file for helping with RE MRE VXP files in IDA
# By giangvinhloc610

import idautils
import ida_funcs
import idc

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
				idc.set_name(ida_funcs.get_func(ref.frm).start_ea, idc.get_strlit_contents(ea).decode("utf-8"))
			except Exception as e:
				break

			# Then break out of the loop
			break
