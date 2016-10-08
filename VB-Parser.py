# Script    : VB Exe Parser
# Version   : 1.0
# Author    : Vic P. aka vic4key
# Date      : Oct 2016
# E-mail:   : vic4key[at]gmail.com
# Blog      : http://viclab.biz/
# Website   : http://cin1team.biz/

import ctypes, inspect

class CVBHeader(ctypes.Structure):
    _fields_ = [
        ("szVbMagic", ctypes.c_ubyte*4),           # 0x0.  "VB5!"" String
        ("wRuntimeBuild", ctypes.c_ushort),        # 0x4.  Build of the VB6 Runtime
        ("szLangDll", ctypes.c_ubyte*14),          # 0x6.  Language Extension DLL
        ("szSecLangDll", ctypes.c_ubyte*14),       # 0x14. 2nd Language Extension DLL
        ("wRuntimeRevision", ctypes.c_ushort),     # 0x22. Internal Runtime Revision
        ("dwLCID", ctypes.c_ulong),                # 0x24. LCID of Language DLL
        ("dwSecLCID", ctypes.c_ulong),             # 0x28. LCID of 2nd Language DLL
        ("lpSubMain", ctypes.c_ulong),             # 0x2C. Pointer to Sub Main Code
        ("lpProjectData", ctypes.c_ulong),         # 0x30. Pointer to Project Data
        ("fMdlIntCtls", ctypes.c_ulong),           # 0x34. VB Control Flags for IDs < 32
        ("fMdlIntCtls2", ctypes.c_ulong),          # 0x38. VB Control Flags for IDs > 32
        ("dwThreadFlags", ctypes.c_ulong),         # 0x3C. Threading Mode
        ("dwThreadCount", ctypes.c_ulong),         # 0x40. Threads to support in pool
        ("wFormCount", ctypes.c_ushort),           # 0x44. Number of forms present
        ("wExternalCount", ctypes.c_ushort),       # 0x46. Number of external controls
        ("dwThunkCount", ctypes.c_ulong),          # 0x48. Number of thunks to create
        ("lpGuiTable", ctypes.c_ulong),            # 0x4C. Pointer to GUI Table
        ("lpExternalTable", ctypes.c_ulong),       # 0x50. Pointer to External Table
        ("lpComRegisterData", ctypes.c_ulong),     # 0x54. Pointer to COM Information
        ("bSZProjectDescription", ctypes.c_ulong), # 0x58. Offset to Project Description
        ("bSZProjectExeName", ctypes.c_ulong),     # 0x5C. Offset to Project EXE Name
        ("bSZProjectHelpFile", ctypes.c_ulong),    # 0x60. Offset to Project Help File
        ("bSZProjectName", ctypes.c_ulong)         # 0x64. Offset to Project Name
    ]

class CVBProjectInfo(ctypes.Structure):
    _fields_ = [
        ("dwVersion", ctypes.c_ulong),             # 0x0.   5.00 in Hex (0x1F4). Version.
        ("lpObjectTable", ctypes.c_ulong),         # 0x4.   Pointer to the Object Table
        ("dwNull", ctypes.c_ulong),                # 0x8.   Unused value after compilation.
        ("lpCodeStart", ctypes.c_ulong),           # 0xC.   Points to start of code. Unused.
        ("lpCodeEnd", ctypes.c_ulong),             # 0x10.  Points to end of code. Unused.
        ("dwDataSize", ctypes.c_ulong),            # 0x14.  Size of VB Object Structures. Unused.
        ("lpThreadSpace", ctypes.c_ulong),         # 0x18.  Pointer to Pointer to Thread Object.
        ("lpVbaSeh", ctypes.c_ulong),              # 0x1C.  Pointer to VBA Exception Handler
        ("lpNativeCode", ctypes.c_ulong),          # 0x20.  Pointer to .DATA section.
        ("szPathInformation", ctypes.c_ubyte*528), # 0x24.  Contains Path and ID string. < SP6
        ("lpExternalTable", ctypes.c_ulong),       # 0x234. Pointer to External Table.
        ("dwExternalCount", ctypes.c_ulong)        # 0x238. Objects in the External Table.
    ]
    
class CVBProjectInfo2(ctypes.Structure):
    _fields_ = [
        ("lpHeapLink", ctypes.c_ulong),           # 0x0. Unused after compilation, always 0.
        ("lpObjectTable", ctypes.c_ulong),        # 0x4. Back-Pointer to the Object Table.
        ("dwReserved", ctypes.c_ulong),           # 0x8. Always set to -1 after compiling. Unused
        ("dwUnused", ctypes.c_ulong),             # 0xC. Not written or read in any case.
        ("lpObjectList", ctypes.c_ulong),         # 0x10. Pointer to Object Descriptor Pointers.
        ("dwUnused2", ctypes.c_ulong),            # 0x14. Not written or read in any case.
        ("szProjectDescription", ctypes.c_ulong), # 0x18. Pointer to Project Description
        ("szProjectHelpFile", ctypes.c_ulong),    # 0x1C. Pointer to Project Help File
        ("dwReserved2", ctypes.c_ulong),          # 0x20. Always set to -1 after compiling. Unused
        ("dwHelpContextId", ctypes.c_ulong)       # 0x24. Help Context ID set in Project Settings.
    ]

class CVBObjectTable(ctypes.Structure):
    _fields_ = [
        ("lpHeapLink", ctypes.c_ulong),         # 0x0.  Unused after compilation, always 0.
        ("lpExecProj", ctypes.c_ulong),         # 0x4.  Pointer to VB Project Exec COM Object.
        ("lpProjectInfo2", ctypes.c_ulong),     # 0x8.  Secondary Project Information.
        ("dwReserved", ctypes.c_ulong),         # 0xC.  Always set to -1 after compiling. Unused.
        ("dwNull", ctypes.c_ulong),             # 0x10. Not used in compiled mode.
        ("lpProjectObject", ctypes.c_ulong),    # 0x14. Pointer to in-memory Project Data.
        ("uuidObject", ctypes.c_ubyte*16),      # 0x18. GUID of the Object Table.
        ("fCompileState", ctypes.c_ushort),     # 0x28. Internal flag used during compilation.
        ("dwTotalObjects", ctypes.c_ushort),    # 0x2A. Total objects present in Project.
        ("dwCompiledObjects", ctypes.c_ushort), # 0x2C. Equal to above after compiling.
        ("dwObjectsInUse", ctypes.c_ushort),    # 0x2E. Usually equal to above after compile.
        ("lpObjectArray", ctypes.c_ulong),      # 0x30. Pointer to Object Descriptors
        ("fIdeFlag", ctypes.c_ulong),           # 0x34. Flag/Pointer used in IDE only.
        ("lpIdeData", ctypes.c_ulong),          # 0x38. Flag/Pointer used in IDE only.
        ("lpIdeData2", ctypes.c_ulong),         # 0x3C. Flag/Pointer used in IDE only.
        ("lpszProjectName", ctypes.c_ulong),    # 0x40. Pointer to Project Name.
        ("dwLcid", ctypes.c_ulong),             # 0x44. LCID of Project.
        ("dwLcid2", ctypes.c_ulong),            # 0x48. Alternate LCID of Project.
        ("lpIdeData3", ctypes.c_ulong),         # 0x4C. Flag/Pointer used in IDE only.
        ("dwIdentifier", ctypes.c_ulong)        # 0x50. Template Version of Structure.
    ]

class CVBPublicObjectDescriptors(ctypes.Structure):
    _fields_ = [
        ("lpObjectInfo", ctypes.c_ulong),   # 0x0.  Pointer to the Object Info for this Object.
        ("dwReserved", ctypes.c_ulong),     # 0x4.  Always set to -1 after compiling.
        ("lpPublicBytes", ctypes.c_ulong),  # 0x8.  Pointer to Public Variable Size integers.
        ("lpStaticBytes", ctypes.c_ulong),  # 0xC.  Pointer to Static Variable Size integers.
        ("lpModulePublic", ctypes.c_ulong), # 0x10. Pointer to Public Variables in DATA section
        ("lpModuleStatic", ctypes.c_ulong), # 0x14. Pointer to Static Variables in DATA section
        ("lpszObjectName", ctypes.c_ulong), # 0x18. Name of the Object.
        ("dwMethodCount", ctypes.c_ulong),  # 0x1C. Number of Methods in Object.
        ("lpMethodNames", ctypes.c_ulong),  # 0x20. If present, pointer to Method names array.
        ("bStaticVars", ctypes.c_ulong),    # 0x24. Offset to where to copy Static Variables.
        ("fObjectType", ctypes.c_ulong),    # 0x28. Flags defining the Object Type.
        ("dwNull", ctypes.c_ulong)          # 0x2C. Not valid after compilation
    ]

class CVBPrivateObjectDescriptors(ctypes.Structure):
    _fields_ = [
        ("lpHeapLink", ctypes.c_ulong),      # 0x0. Unused after compilation, always 0.
        ("lpObjectInfo", ctypes.c_ulong),    # 0x4. Pointer to the Object Info for this Object.
        ("dwReserved", ctypes.c_ulong),      # 0x8. Always set to -1 after compiling.
        ("dwIdeData", ctypes.c_ulong*3),     # 0xC. Not valid after compilation.
        ("lpObjectList", ctypes.c_ulong),    # 0x18. Points to the Parent Structure (Array)
        ("dwIdeData2", ctypes.c_ulong),      # 0x1C. Not valid after compilation.
        ("lpObjectList2", ctypes.c_ulong*3), # 0x20. Points to the Parent Structure (Array).
        ("dwIdeData3", ctypes.c_ulong*3),    # 0x2C. Not valid after compilation.
        ("dwObjectType", ctypes.c_ulong),    # 0x38. Type of the Object described.
        ("dwIdentifier", ctypes.c_ulong)     # 0x3C. Template Version of Structure.
    ]

class CVBObjectInfo(ctypes.Structure):
    _fields_ = [
        ("wRefCount", ctypes.c_ushort),      # 0x0.  Always 1 after compilation.
        ("wObjectIndex", ctypes.c_ushort),   # 0x2.  Index of this Object.
        ("lpObjectTable", ctypes.c_ulong),   # 0x4.  Pointer to the Object Table
        ("lpIdeData", ctypes.c_ulong),       # 0x8.  Zero after compilation. Used in IDE only.
        ("lpPrivateObject", ctypes.c_ulong), # 0xC.  Pointer to Private Object Descriptor.
        ("dwReserved", ctypes.c_ulong),      # 0x10. Always -1 after compilation.
        ("dwNull", ctypes.c_ulong),          # 0x14. Unused.
        ("lpObject", ctypes.c_ulong),        # 0x18. Back-Pointer to Public Object Descriptor.
        ("lpProjectData", ctypes.c_ulong),   # 0x1C. Pointer to in-memory Project Object.
        ("wMethodCount", ctypes.c_ushort),   # 0x20. Number of Methods
        ("wMethodCount2", ctypes.c_ushort),  # 0x22. Zeroed out after compilation. IDE only.
        ("lpMethods", ctypes.c_ulong),       # 0x24. Pointer to Array of Methods.
        ("wConstants", ctypes.c_ushort),     # 0x28. Number of Constants in Constant Pool.
        ("wMaxConstants", ctypes.c_ushort),  # 0x2A. Constants to allocate in Constant Pool.
        ("lpIdeData2", ctypes.c_ulong),      # 0x2C. Valid in IDE only.
        ("lpIdeData3", ctypes.c_ulong),      # 0x30. Valid in IDE only.
        ("lpConstants", ctypes.c_ulong)      # 0x34. Pointer to Constants Pool.
    ]
    
class CVBOptionalObjectInfo(ctypes.Structure):
    _fields_ = [
        ("dwObjectGuids", ctypes.c_ulong),      # 0x0. How many GUIDs to Register. 2 = Designer
        ("lpObjectGuid", ctypes.c_ulong),       # 0x4. Unique GUID of the Object *VERIFY*
        ("dwNull", ctypes.c_ulong),             # 0x8. Unused.
        ("lpuuidObjectTypes", ctypes.c_ulong),  # 0xC. Pointer to Array of Object Interface GUIDs
        ("dwObjectTypeGuids", ctypes.c_ulong),  # 0x10. How many GUIDs in the Array above.
        ("lpControls2", ctypes.c_ulong),        # 0x14. Usually the same as lpControls.
        ("dwNull2", ctypes.c_ulong),            # 0x18. Unused.
        ("lpObjectGuid2", ctypes.c_ulong),      # 0x1C. Pointer to Array of Object GUIDs.
        ("dwControlCount", ctypes.c_ulong),     # 0x20. Number of Controls in array below.
        ("lpControls", ctypes.c_ulong),         # 0x24. Pointer to Controls Array.
        ("wEventCount", ctypes.c_ushort),       # 0x28. Number of Events in Event Array.
        ("wPCodeCount", ctypes.c_ushort),       # 0x2A. Number of P-Codes used by this Object.
        ("bWInitializeEvent", ctypes.c_ushort), # 0x2C. Offset to Initialize Event from Event Table.
        ("bWTerminateEvent", ctypes.c_ushort),  # 0x2E. Offset to Terminate Event in Event Table.
        ("lpEvents", ctypes.c_ulong),           # 0x30. Pointer to Events Array.
        ("lpBasicClassObject", ctypes.c_ulong), # 0x34. Pointer to in-memory Class Objects.
        ("dwNull3", ctypes.c_ulong),            # 0x38. Unused.
        ("lpIdeData", ctypes.c_ulong)           # 0x3C. Only valid in IDE.
    ]
    
class CVBControlInfo(ctypes.Structure):
    _fields_ = [
        #("wFlagImplement", ctypes.c_ushort),
        #("wEventHandlerCount", ctypes.c_ushort),
        #("wFlagIndexRef", ctypes.c_ushort),
        
        #("fControlType", ctypes.c_ulong),   # 0x0.  Type of control.
        
        ("wUnused", ctypes.c_ushort),        # 0x0.  Type of control. # Mine
        ("fControlType", ctypes.c_ushort),   # 0x0.  Type of control. # Mine
        
        ("wEventcount", ctypes.c_ushort),    # 0x4.  Number of Event Handlers supported.
        ("bWEventsOffset", ctypes.c_ushort), # 0x6.  Offset in to Memory struct to copy Events.
        ("lpGuid", ctypes.c_ulong),          # 0x8.  Pointer to GUID of this Control.
        ("dwIndex", ctypes.c_ulong),         # 0xC.  Index ID of this Control.
        ("dwNull", ctypes.c_ulong),          # 0x10. Unused.
        ("dwNull2", ctypes.c_ulong),         # 0x14. Unused.
        ("lpEventTable", ctypes.c_ulong),    # 0x18. Pointer to Event Handler Table.
        ("lpIdeData", ctypes.c_ulong),       # 0x1C. Valid in IDE only.
        ("lpszName", ctypes.c_ulong),        # 0x20. Name of this Control.
        ("dwIndexCopy", ctypes.c_ulong)      # 0x24. Secondary Index ID of this Control
    ]

class CVBEventHandlerTable(ctypes.Structure):
    _fields_ = [
        ("dwNull", ctypes.c_ulong),         # 0x0. Unused
        ("lpControls", ctypes.c_ulong),     # 0x4. refer to CVBControlInfo  / Controls List
        ("lpObjectInfo", ctypes.c_ulong),   # 0x8. refer to CVBObjectInfo   / Form Descriptor
        ("lpEVENT_SINK_QueryInterface", ctypes.c_ulong), # 0xC.
        ("lpEVENT_SINK_Release", ctypes.c_ulong),        # 0x10.
        ("lpRelease", ctypes.c_ulong)       # 0x14.
    ]

class CVBGUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),  # Specifies the first 8 hexadecimal digits of the GUID.
        ("Data2", ctypes.c_ushort), # Specifies the first group of 4 hexadecimal digits.
        ("Data3", ctypes.c_ushort), # Specifies the second group of 4 hexadecimal digits.
        ("Data4", ctypes.c_ubyte*8) # Array of 8 bytes. The first 2 bytes contain the third group of 4 hexadecimal digits.
                                    # The remaining 6 bytes contain the final 12 hexadecimal digits.
    ]

MDLInternalControlFlags = [
    (0x00, 0x00000001, "PictureBox Object"),
    (0x01, 0x00000002, "Label Object"),
    (0x02, 0x00000004, "TextBox Object"),
    (0x03, 0x00000008, "Frame Object"),
    (0x04, 0x00000010, "CommandButton Object"),
    (0x05, 0x00000020, "CheckBox Object"),
    (0x06, 0x00000040, "OptionButton Object"),
    (0x07, 0x00000080, "ComboBox Object"),
    (0x08, 0x00000100, "ListBox Object"),
    (0x09, 0x00000200, "HScrollBar Object"),
    (0x0A, 0x00000400, "VScrollBar Object"),
    (0x0B, 0x00000800, "Timer Object"),
    (0x0C, 0x00001000, "Print Object"),
    (0x0D, 0x00002000, "Form Object"),
    (0x0E, 0x00004000, "Screen Object"),
    (0x0F, 0x00008000, "Clipboard Object"),
    (0x10, 0x00010000, "Drive Object"),
    (0x11, 0x00020000, "Dir Object"),
    (0x12, 0x00040000, "FileListBox Object"),
    (0x13, 0x00080000, "Menu Object"),
    (0x14, 0x00100000, "MDIForm Object"),
    (0x15, 0x00200000, "App Object"),
    (0x16, 0x00400000, "Shape Object"),
    (0x17, 0x00800000, "Line Object"),
    (0x18, 0x01000000, "Image Object"),
    (0x19, 0x02000000, "Unsupported"),
    (0x1A, 0x04000000, "Unsupported"),
    (0x1B, 0x08000000, "Unsupported"),
    (0x1C, 0x10000000, "Unsupported"),
    (0x1D, 0x20000000, "Unsupported"),
    (0x1E, 0x40000000, "Unsupported"),
    (0x1F, 0x80000000, "Unsupported")
]

CtrlFlags = [
    (0x00, 0x0000001A, "PictureBox"),
    (0x01, 0x00000012, "Label"),
    (0x02, 0x00000018, "TextBox"),
    (0x03, 0x0000000D, "Frame"),
    (0x04, 0x00000011, "CommandButton"),
    (0x05, 0x00000000, "CheckBox"),
    (0x06, 0x00000013, "OptionButton"),
    (0x07, 0x00000000, "ComboBox"),
    (0x08, 0x00000015, "ListBox"),
    (0x09, 0x00000000, "HScrollBar"),
    (0x0A, 0x00000000, "VScrollBar"),
    (0x0B, 0x00000001, "Timer"),
    (0x0C, 0x00000000, "Print"),
    (0x0D, 0x00000000, "Form"),
    (0x0E, 0x00000000, "Screen"),
    (0x0F, 0x00000000, "Clipboard"),
    (0x10, 0x00000000, "Drive"),
    (0x11, 0x00000014, "Dir"),
    (0x12, 0x00000000, "FileListBox"),
    (0x13, 0x00000000, "Menu"),
    (0x14, 0x00000000, "MDIForm"),
    (0x15, 0x00000000, "App"),
    (0x16, 0x00000000, "Shape"),
    (0x17, 0x00000000, "Line"),
    (0x18, 0x0000000D, "Image"),
    (0x19, 0x0000001D, "Grid"),
    (0x1A, 0x00000016, "StatusBar"),
    (0x1B, 0x0000000A, "Communication"),
    (0x1C, 0x00000000, "Unsupported"),
    (0x1D, 0x00000000, "Unsupported"),
    (0x1E, 0x00000000, "Unsupported"),
    (0x1F, 0x00000000, "Unsupported")
]

'''
[ # 2nd Flag Zone 2nd Flag Zone 2nd Flag Zone
    (0x20, 0x00000001, "Unsupported"),
    (0x21, 0x00000002, "Unsupported"),
    (0x22, 0x00000004, "Unsupported"),
    (0x23, 0x00000008, "Unsupported"),
    (0x24, 0x00000010, "Unsupported"),
    (0x25, 0x00000020, "DataQuery Object"),
    (0x26, 0x00000040, "OLE Object"),
    (0x27, 0x00000080, "Unsupported"),
    (0x28, 0x00000100, "UserControl Object"),
    (0x29, 0x00000200, "PropertyPage Object"),
    (0x2A, 0x00000400, "Document Object"),
    (0x2B, 0x00000800, "Unsupported")
]
'''

CtrlButtonEvents = {
    0x0: "Click",
    0x1: "DragDrop",
    0x2: "DragOver",
    0x3: "GotFocus",
    0x4: "KeyDown",
    0x5: "KeyPress",
    0x6: "KeyUp",
    0x7: "LostFocus",
    0x8: "MouseDown",
    0x9: "MouseMove",
    0xA: "MouseUp",
    0xB: "OLEDragOver",
    0xC: "OLEDragDrop",
    0xD: "OLEGiveFeedback",
    0xE: "OLEStartDrag",
    0xF: "OLESetData",
    0x10: "OLECompleteDrag"
}

CtrlTextboxEvents = {
    0x0: "Change",
    0x1: "DragDrop",
    0x2: "DragOver",
    0x3: "GotFocus",
    0x4: "KeyDown",
    0x5: "KeyPress",
    0x6: "KeyUp",
    0x7: "LinkClose",
    0x8: "LinkError",
    0x9: "LinkOpen",
    0xA: "LostFocus",
    0xB: "LinkNotify",
    0xC: "MouseDown",
    0xD: "MouseMove",
    0xE: "MouseUp",
    0xF: "Click",
    0x10: "DblClick",
    0x11: "OLEDragOver",
    0x12: "OLEDragDrop",
    0x13: "OLEGiveFeedback",
    0x14: "OLEStartDrag",
    0x15: "OLESetData",
    0x16: "OLECompleteDrag",
    0x17: "Validate"
}

CtrlFormEvents = {
    0x0: "DragDrop",
    0x1: "DragOver",
    0x2: "LinkClose",
    0x3: "LinkError",
    0x4: "LinkExecute",
    0x5: "LinkOpen",
    0x6: "Load",
    0x7: "Resize",
    0x8: "Unload",
    0x9: "QueryUnload",
    0xA: "Activate",
    0xB: "Deactivate",
    0xC: "Click",
    0xD: "DblClick",
    0xE: "GotFocus",
    0xF: "KeyDown",
    0x10: "KeyPress",
    0x11: "KeyUp",
    0x12: "LostFocus",
    0x13: "MouseDown",
    0x14: "MouseMove",
    0x15: "MouseUp",
    0x16: "Paint",
    0x17: "Initialize",
    0x18: "Terminate",
    0x19: "OLEDragOver",
    0x1A: "OLEDragDrop",
    0x1B: "OLEGiveFeedback",
    0x1C: "OLEStartDrag",
    0x1D: "OLESetData",
    0x1E: "OLECompleteDrag"
}

CtrlFileEvents = {
    0x0: "Click",
    0x1: "DblClick",
    0x2: "DragDrop",
    0x3: "DragOver",
    0x4: "GotFocus",
    0x5: "KeyDown",
    0x6: "KeyPress",
    0x7: "KeyUp",
    0x8: "LostFocus",
    0x9: "MouseDown",
    0xA: "MouseMove",
    0xB: "MouseUp",
    0xC: "PathChange",
    0xD: "PatternChange",
    0xE: "OLEDragOver",
    0xF: "OLEDragDrop",
    0x10: "OLEGiveFeedback",
    0x11: "OLEStartDrag",
    0x12: "OLESetData",
    0x13: "OLECompleteDrag",
    0x14: "Scroll",
    0x15: "Validate"
}

CtrlOptionEvents = {
    0x0: "Click",
    0x1: "DblClick",
    0x2: "DragDrop",
    0x3: "DragOver",
    0x4: "GotFocus",
    0x5: "KeyDown",
    0x6: "KeyPress",
    0x7: "KeyUp",
    0x8: "LostFocus",
    0x9: "MouseDown",
    0xA: "MouseMove",
    0xB: "MouseUp",
    0xC: "OLEDragOver",
    0xD: "OLEDragDrop",
    0xE: "OLEGiveFeedback",
    0xF: "OLEStartDrag",
    0x10: "OLESetData",
    0x11: "OLECompleteDrag",
    0x12: "Validate"
}

CtrlComboEvents = {
    0x0: "Change",
    0x1: "Click",
    0x2: "DblClick",
    0x3: "DragDrop",
    0x4: "DragOver",
    0x5: "DropDown",
    0x6: "GotFocus",
    0x7: "KeyDown",
    0x8: "KeyPress",
    0x9: "KeyUp",
    0xA: "LostFocus",
    0xB: "OLEDragOver",
    0xC: "OLEDragDrop",
    0xD: "OLEGiveFeedback",
    0xE: "OLEStartDrag",
    0xF: "OLESetData",
    0x10: "OLECompleteDrag",
    0x11: "Scroll",
    0x12: "Validate"
}

CtrlLabelEvents = {
    0x0: "Change",
    0x1: "Click",
    0x2: "DblClick",
    0x3: "DragDrop",
    0x4: "DragOver",
    0x5: "LinkClose",
    0x6: "LinkError",
    0x7: "LinkOpen",
    0x8: "MouseDown",
    0x9: "MouseMove",
    0xA: "MouseUp",
    0xB: "LinkNotify",
    0xC: "OLEDragOver",
    0xD: "OLEDragDrop",
    0xE: "OLEGiveFeedback",
    0xF: "OLEStartDrag",
    0x10: "OLESetData",
    0x11: "OLECompleteDrag"
}

CtrlMenuEvents = {
    0x0: "Click"
}

CtrlTimerEvents = {
    0x0: "Timer"
}

CT_BUTTON       = 0x33AD4EF2
CT_TEXTBOX      = 0x33AD4EE2
CT_TIMER        = 0x33AD4F2A
CT_FORM         = 0x33AD4F3A
CT_FILE         = 0x33AD4F62
CT_OPTION       = 0x33AD4F02
CT_COMBOBOX     = 0x33AD4F03
CT_COMBOBOX2    = 0x33AD4F0A
CT_MENU         = 0x33AD4F6A
CT_LABEL        = 0x33AD4EDA

CtrlEvents = {
    CT_BUTTON       : CtrlButtonEvents,
    CT_TEXTBOX      : CtrlTextboxEvents,
    CT_TIMER        : CtrlTimerEvents,
    CT_FORM         : CtrlFormEvents,
    CT_FILE         : CtrlFileEvents,
    CT_OPTION       : CtrlOptionEvents,
    CT_COMBOBOX     : CtrlComboEvents,
    CT_COMBOBOX2    : CtrlComboEvents,
    CT_MENU         : CtrlMenuEvents,
    CT_LABEL        : CtrlLabelEvents
}

B2S = lambda M: "".join(map(chr, M))

HF_LENGTH = 100 # Header & Footer : Fixed Length

def STATUS():
    list_caller_info = inspect.getouterframes(inspect.currentframe())
    if len(list_caller_info) > 1: caller_info = list_caller_info[1]
    else: return ("", "", -1)
    u0, u1, line_number, function_name, u2, u3 = caller_info[0:len(caller_info)]
    result = (function_name, line_number)
    return result

def ParseStructure(a, t):
    p = GetManyBytes(a, sizeof(t))
    if p == 0: return None
    return ctypes.cast(p, ctypes.POINTER(t)).contents

'''
def GetDWORD(address, min_address = 0, max_address = 0):
    if min_address == 0:
        min_address = MinEA()
        if min_address == 0: return 0
    if max_address == 0:
        max_address = MinEA()
        if max_address == 0: return 0
    if min_address <= address <= max_address: return Dword(address)
    else: return 0
'''

def GetControlDescriptionByTypeID(TypeID):
    result = ""
    for e in CtrlFlags:
        index, typeid, description = e[0:len(e)]
        if typeid == TypeID:
            if len(result) != 0: result += (" or " + description)
            else: result = description
    return result
    
def CreateFunction(address, name):
    result = True
    result &= MakeFunction(address)
    result &= MakeName(address, name)
    return result

def GetEventByID(ctrl_type, event_id):
    ctrl_events, result = None, "Unknown"
    for ctrlType in CtrlEvents.keys():
        if ctrlType == ctrl_type:
            ctrl_events = CtrlEvents[ctrlType]
            break
    if ctrl_events == None: return result
    for eventID in ctrl_events.keys():
        if eventID == event_id:
            result = ctrl_events[eventID]
            break
    return result

def main():
    print " VB Exe Parser ".center(HF_LENGTH, "-")
    
    OEO = GetEntryOrdinal(0)
    OEP = GetEntryPoint(OEO)
    print "%08X -> `OEP`" % OEP
    
    MIN, MAX = MinEA(), MaxEA()
    IsAddressValid = lambda address: MIN <= address <= MAX
    
    ### VB HEADER
    addr_vb_header = GetOperandValue(OEP, 0);
    if not IsAddressValid(addr_vb_header): return STATUS()
    print "%08X -> `VB HEADER`" % addr_vb_header
    
    VBHeader = ParseStructure(addr_vb_header, CVBHeader)
    print "\tSignature : '%s'" % B2S(VBHeader.szVbMagic)
    
    ### PROJECT INFO ###
    if not IsAddressValid(VBHeader.lpProjectData): return STATUS()
    print "%08X -> `PROJECT INFO`" % VBHeader.lpProjectData
    VBProjectInfo = ParseStructure(VBHeader.lpProjectData, CVBProjectInfo)
    print "\tVersion : %08X" % VBProjectInfo.dwVersion
    
    ### OBJECT TABLE ###
    if not IsAddressValid(VBProjectInfo.lpObjectTable): return STATUS()
    print "%08X -> `OBJECT TABLE`" % VBProjectInfo.lpObjectTable
    VBObjectTable = ParseStructure(VBProjectInfo.lpObjectTable, CVBObjectTable)
    print "\tProject Name: '%s'" % GetString(VBObjectTable.lpszProjectName)
    print "\tTotal Objects: %d" % VBObjectTable.dwTotalObjects
    
    ### PUBLIC OBJECT DESCRIPTORS ###
    if not IsAddressValid(VBObjectTable.lpObjectArray): return STATUS()
    #VBPublicObjectDescriptors = []
    for i in xrange(0, VBObjectTable.dwTotalObjects):
        addr_vb_public_object_descriptors = VBObjectTable.lpObjectArray + i*sizeof(CVBPublicObjectDescriptors)
        if not IsAddressValid(addr_vb_public_object_descriptors): return STATUS()
        print "%08X -> `PUBLIC OBJECT DESCRIPTORS #%d`" % (addr_vb_public_object_descriptors, i)
        VBPublicObjectDescriptor = ParseStructure(addr_vb_public_object_descriptors, CVBPublicObjectDescriptors)
        #VBPublicObjectDescriptors.append(VBPublicObjectDescriptor)
        object_name = GetString(VBPublicObjectDescriptor.lpszObjectName)
        print "\tObject Name: '%s' (%d)" % (object_name, VBPublicObjectDescriptor.dwMethodCount)
        #if object_name != "Form1": continue
        # Methods
        print "\t%08X -> Methods (%d)" % (VBPublicObjectDescriptor.lpMethodNames, VBPublicObjectDescriptor.dwMethodCount)
        for j in xrange(0, VBPublicObjectDescriptor.dwMethodCount):
            addr_vb_method_name_eat = VBPublicObjectDescriptor.lpMethodNames + j*4
            #if not IsAddressValid(addr_vb_method_name_eat): return STATUS()
            addr_method_name = Dword(addr_vb_method_name_eat)
            if IsAddressValid(addr_method_name):
                method_name = GetString(addr_method_name)
                if method_name == None: method_name = "<None>"
                print "\t\t%08X -> '%s'" % (addr_method_name, method_name)
        
        ### OBJECT INFO ###
        if not IsAddressValid(VBPublicObjectDescriptor.lpObjectInfo): return STATUS()
        print "\t%08X -> `OBJECT_INFO`" % VBPublicObjectDescriptor.lpObjectInfo
        VBObjectInfo = ParseStructure(VBPublicObjectDescriptor.lpObjectInfo, CVBObjectInfo)
        
        ### OPTIONAL OBJECT INFO ###
        addr_vb_optional_object_info = VBPublicObjectDescriptor.lpObjectInfo + sizeof(CVBObjectInfo)
        if VBObjectInfo.lpConstants != addr_vb_optional_object_info:
            if not IsAddressValid(addr_vb_optional_object_info): return STATUS()
            print "\t%08X -> `OPTIONAL OBJECT INFO #%d`" % (addr_vb_optional_object_info, i)
            VBOptionalObjectInfo = ParseStructure(addr_vb_optional_object_info, CVBOptionalObjectInfo)
            
            # Controls
            print "\t\t%08X -> Controls (%d)" % (VBOptionalObjectInfo.lpControls, VBOptionalObjectInfo.dwControlCount)
            for j in xrange(0, VBOptionalObjectInfo.dwControlCount):
                ### CONTROL INFO ###
                addr_vb_control_info = VBOptionalObjectInfo.lpControls + j*sizeof(CVBControlInfo)
                print "\t\t\t%08X -> `CONTROL INFO #%d`" % (addr_vb_control_info, j)

                if IsAddressValid(addr_vb_control_info ):
                    VBControlInfo = ParseStructure(addr_vb_control_info, CVBControlInfo)
                    control_name = GetString(VBControlInfo.lpszName)
                    VBGUID = ParseStructure(VBControlInfo.lpGuid, CVBGUID)
                    control_type = VBGUID.Data1
                    '''
                    if VBControlInfo.dwIndex != 0xFFFFFFFF:
                        print "\t\t\t\t%08X. '%s' (%04X - '%s')" % (\
                            VBControlInfo.dwIndex,\
                            GetString(VBControlInfo.lpszName),\
                            VBControlInfo.fControlType,\
                            GetControlDescriptionByTypeID(VBControlInfo.fControlType)
                        )
                    '''
                    VBEventHandlerTable = ParseStructure(addr_vb_control_info, CVBEventHandlerTable)
                    entry_point = VBControlInfo.lpEventTable + sizeof(CVBEventHandlerTable)
                    for control_id in xrange(0, VBControlInfo.fControlType):
                        p = entry_point + 4*control_id
                        if IsAddressValid(p):
                            addr_event = Dword(p)
                            # 816C24 04 XXXXXXXX    | SUB DWORD PTR SS:[ESP+4h],XXXX
                            # E9 XXXXXXXX           | JMP XXXXXXXX <- This is real address of event
                            if IsAddressValid(addr_event):
                                stub = Dword(addr_event) & 0xFFFFFF00
                                if stub == 0x04246C00:  # SUB DWORD PTR SS:[ESP+4h]
                                    stub = Byte(addr_event + 8)
                                    if stub == 0xE9:    # JMP
                                        event_rel = Dword(addr_event + 8 + 1)
                                        event = addr_event + 8 + event_rel + 5
                                        #print "\t\t\t\t%08X -> %s_[%08X]" % (addr_event, control_name, event)
                                        event_name = "fn_%s_%s_%s" % (object_name, control_name, GetEventByID(control_type, control_id))
                                        print "\t\t\t\t%08X -> %s" % (addr_event, event_name)
                                        CreateFunction(event, event_name)

            # Events
            print "\t\t%08X -> Events (%d)" % (VBOptionalObjectInfo.lpEvents, VBOptionalObjectInfo.wEventCount)
            for j in xrange(0, VBOptionalObjectInfo.wEventCount):
                addr_vb_event = VBOptionalObjectInfo.lpEvents + j*4
                if not IsAddressValid(addr_vb_event): return STATUS()
                event_eat = Dword(addr_vb_event) # eat: event address table
                if not IsAddressValid(event_eat): return STATUS()
                
                # This method belongs VB Table or User Defined? 0xFFFF -> User Defined.
                addr_magic = event_eat - 4
                if not IsAddressValid(addr_magic): return STATUS()
                magic = Dword(addr_magic)
                is_user_defined = (magic == 0xFFFF)
                
                # Get the destination address of this jump instruction
                if Byte(event_eat) == 0xE9: # JMP
                    event_rel = Dword(event_eat + 1)
                    #event = 0
                    #if (event_rel & 0xFFFF0000) >> 2**4 != 0xFFFF: event = event_eat + event_rel + 5
                    #else: pass # not verified
                    event = event_eat + event_rel + 5
                    if is_user_defined == True:
                        event_name = "fn_Unknown_%08X" % event
                        print "\t\t\t%08X -> %s" % (event_eat, event_name)
                        CreateFunction(event, event_name)
                    else: print "\t\t\t%08X -> %08X (refer to #KnownEvent)" % (event_eat, event)
                
            # GUIDs
            print "\t\t%08X -> GUIDs (%d)" % (VBOptionalObjectInfo.lpObjectGuid2, VBOptionalObjectInfo.dwObjectGuids)
            for j in xrange(0, VBOptionalObjectInfo.dwObjectGuids):
                addr_vb_guid = VBOptionalObjectInfo.lpObjectGuid2 + j*4
                if not IsAddressValid(addr_vb_guid): return STATUS()
                print "\t\t\t%08X -> GUID #%d" % (Dword(addr_vb_guid), j)

    print " Done ".center(HF_LENGTH, "-")
    return

if __name__ == "__main__": print main()