#Make bookmarks for all X-references of vulnerable functions
#in current program
#@author 
#@category CodeAnalysis
#@keybinding 
#@menupath
#@toolbar 

sinks = [					
    'strcpy', 'strncpy',
    'memcpy',
    'gets',
    'memmove',
    'scanf',
    'strcpyA', 
    'strcpyW', 
    'wcscpy', 
    '_tcscpy', 
    '_mbscpy', 
    'StrCpy', 
    'StrCpyA',
    'lstrcpyA',
    'lstrcpy',
    'exec', 
]

duplicate = []
fm = currentProgram.getFunctionManager()
bm = currentProgram.getBookmarkManager()
ext_fm = fm.getExternalFunctions()

while ext_fm.hasNext():
    ext_func = ext_fm.next()
    target_func = ext_func.getName()

    if target_func in sinks and target_func not in duplicate:
        duplicate.append(target_func)
        loc = ext_func.getExternalLocation()

        sink_func_addr = loc.getAddress()
        if sink_func_addr is None:
            sink_func_addr = ext_func.getFunctionThunkAddresses()[0]
        if sink_func_addr is None:
            sink_func_addr = ext_func.getEntryPoint()

        if sink_func_addr is not None:
            references = getReferencesTo(sink_func_addr)
            for ref in references:
                bm.setBookmark(
                    ref.getFromAddress(),
                    'Warning', # type
                    'Vulnerability', # category
                    target_func # description
                )

