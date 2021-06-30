//Make bookmarks for all X-references of vulnerable functions
//in current program
//@author
//@category CodeAnalysis
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class BookmarkVulnerableFunctions extends GhidraScript {
	public void run() throws Exception {
		final String[] sPatterns = {
			"strcpy", "strncpy",
			"memcpy",
			"gets",
			"memmove",
			"scanf",
			"strcpyA",
			"strcpyW",
			"wcscpy",
			"_tcscpy",
			"_mbscpy",
			"StrCpy",
			"StrCpyA",
			"lstrcpyA",
			"lstrcpy",
			"exec"
		};
		ArrayList<String> lPattern = new ArrayList<String>();
		for(String pattern: sPatterns) {
			lPattern.add(pattern);
		}

		ArrayList<String> lDuplicate = new ArrayList<String>();
		GhidraState state = getState();
		Program curPgm = state.getCurrentProgram();
		BookmarkManager bookmarkMgr = curPgm.getBookmarkManager();
		FunctionManager funcMgr = curPgm.getFunctionManager();
		FunctionIterator iExtFunc = funcMgr.getExternalFunctions();

		while(iExtFunc.hasNext() == true) {
			Function extFunc = iExtFunc.next();
			String sFuncName = extFunc.getName();

			// Skip the loop
			if(!lPattern.contains(sFuncName)) continue;
			if(lDuplicate.contains(sFuncName)) continue;

			lDuplicate.add(sFuncName);

			Address vulnFunc = extFunc.getFunctionThunkAddresses()[0];
			Reference[] references = getReferencesTo(vulnFunc);

			for(Reference ref: references) {
				bookmarkMgr.setBookmark(
					ref.getFromAddress(),
					"Warning", // type
					"Vulnerability", // category
					sFuncName // description
				);
			}
		}
	}
}