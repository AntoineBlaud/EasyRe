import contextlib
import json
import logging
import os
import signal
from statistics import variance
import struct
import sys
import threading
import time
from atexit import register
from collections import OrderedDict
from concurrent.futures import thread
from dataclasses import dataclass
from typing import List

import easygui
import ida_bytes
import ida_dbg
import ida_hexrays
import ida_nalt
import idaapi
import idautils
import idc
import ida_xref
import PyQt5
from cv2 import add, trace
from idaapi import PluginForm
from idna import valid_label_length
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication
from functools import wraps
from enum import IntEnum
import pprint

"""_summary_ = "EasyRE"
_author_ = "Antoine Blaud (@d0raken)"
"""


@dataclass
class GarbageValues:
    """_summary_
    Contains the garbage global values used in this script.
    """
    x64_register_names = [
        'RAX', 'RBX', 'RCX', 'RDX', 'RSP', 'RBP', 'RSI', 'RDI', 'R8', 'R9',
        'R10', 'R11', 'R12', 'R13', 'R14', 'R15'
    ]
    x86_register_names = [
        'EAX', 'EBX', 'ECX', 'EDX', 'ESP', 'EBP', 'ESI', 'EDI', 'R8D', 'R9D',
        'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D'
    ]
    ret = [
        'ret', 'retn', 'retf', 'iret', 'iretn', 'iretf', 'sysret', 'sysretn',
        'sysretf'
    ]
    MAX_PARENT = 1
    DISCOVERY_TRIES = 0


class GarbageHelper:
    """_summary_
    Contains miscellaneous functions used in this script. Most of them are used to transform
    registers or variables into a new format, in order to be printed or saved into a file.
    """

    @staticmethod
    def ConvertRegistersValues(regs_values):
        """"_summary_
        Convert registers values to a printable dict format.
        """
        values = OrderedDict()
        zfill = 16 if idaapi.get_inf_structure().is_64bit() else 8
        for reg in regs_values:
            values[reg] = hex(regs_values[reg])[2:].zfill(zfill).upper()
        return values

    @staticmethod
    def ConvertVariablesValues(variables, regs_values):
        """"_summary_
        Convert variables values to a printable dict format.
        """

        def Extract(pattern, regs_values, zfill, var, reg):
            # use pattern to try to find the register name and setting value
            with contextlib.suppress(Exception):
                value = hex(regs_values[pattern])[2:].zfill(zfill).upper()
                string = f'{var.name}: {reg} -> {value}'
                found = True
            return found, string

        values = OrderedDict()
        zfill = 16 if idaapi.get_inf_structure().is_64bit() else 8
        for var in variables:
            # if variable is saved into a register
            if len(var.references) > 0:
                reg = var.references[0].upper()
                reg = reg[1:] + 'D' if reg[0] == 'E' else reg
                rv = idaapi.regval_t()
                # following code test if the register exists, and then get the value
                if (idaapi.get_reg_val(reg, rv)):
                    found, string = False, None
                    try:
                        found, string = Extract(
                            reg[:2] if reg[2] == 'D' else reg, regs_values, zfill,
                            var, reg)
                    except:
                        pass
                    try:
                        if not found:
                            found, string = Extract(
                                reg, regs_values, zfill, var, reg)
                    except:
                        pass
                    try:
                        if not found:
                            found, string = Extract(
                                'R' + reg if idaapi.get_inf_structure().is_64bit()
                                else 'E' + reg, regs_values, zfill, var, reg)
                    except:
                        pass
                    try:
                        if not found:
                            string = reg
                        values[var.name] = string
                    except:
                        pass
                # if variable is saved into the stack
                else:
                    try:
                        offset = int(reg[1:])
                        reg = "[%s+0x%s]" % (
                            "rsp", offset) if idaapi.get_inf_structure(
                            ).is_64bit() else "[%s+0x%s]" % ("esp", offset)
                        values[var.name] = reg
                    except ValueError:
                        continue
        return values

    @staticmethod
    def FormatDataDump(**kwargs):
        """_summary_
        Use the dumped data to show the values in different formats (int , str, ptr)
        """
        #addr, ea, functionname, traceevents, index, timestotrace
        addr = kwargs['addr']
        ea = kwargs['ea']
        functionname = kwargs['functionname']
        traceevents = kwargs['traceevents']
        index = kwargs['index']
        timestotrace = kwargs['timestotrace'] 
        for trace in traceevents:
            if trace.functionname != functionname:
                continue
            for k, entry in trace.entries.items():
                
                if k != ea:
                    continue
                index = 0 if timestotrace == 1 else index % timestotrace
                print(index, addr)
                pprint.pprint(entry[index].mem.dump.keys())
                if addr in entry[index].mem.dump:
                    for word in entry[index].mem.dump[addr]:
                        yield GarbageHelper.FormatWord(word)
                return

    @staticmethod
    def CreatePrintableBlock(string):
        block = 18
        size = len(string)
        string = string.ljust(int(size + (block - size) / 2), ).rjust(
            (block), )
        return string

    @staticmethod
    def IntToStr(integer, size):
        integer = hex(integer)[2:].zfill(size * 2)
        result = []
        for e in range(0, 2 * size, 2):
            value = int(integer[e:e + 2], 16)
            if value < 32 or value > 127:
                result.append(chr(46))
                continue
            result.append(chr(value))
        return ''.join(result[::-1])

    @staticmethod
    def FormatWord(word):
        zfill = 8 if idaapi.get_inf_structure().is_64bit() else 4
        hexa = hex(word)[2:].zfill(zfill * 2)
        q = struct.pack('<Q', word)
        signed_int = struct.unpack('<q', q)[0]
        double = struct.unpack('<d', q)[0]
        string = GarbageHelper.IntToStr(word, zfill)
        s = f"{hexa.upper()} "
        s += f"{string} ".rjust(10, ' ')
        s += GarbageHelper.CreatePrintableBlock("{:e}".format(signed_int))
        s += GarbageHelper.CreatePrintableBlock("{:e}".format(double))
        return s


class IdaHelper:
    """_summary_
    Contains miscellaneous functions.
    """

    @staticmethod
    def GetRegistersNames() -> list:
        if idaapi.get_inf_structure().is_64bit():
            return GarbageValues.x64_register_names
        else:
            return GarbageValues.x86_register_names

    @staticmethod
    def GetRegistersValues() -> dict:
        regs = IdaHelper.GetRegistersNames()
        regs_values = {}
        rv = idaapi.regval_t()
        for reg in regs:
            idaapi.get_reg_val(reg, rv)
            regs_values[reg] = rv.ival
        return regs_values

    @staticmethod
    def GetEA() -> tuple:
        rv = idaapi.regval_t()
        if idaapi.get_inf_structure().is_64bit():
            idaapi.get_reg_val('RIP', rv)
        else:
            idaapi.get_reg_val('EIP', rv)
        functionname = idaapi.get_func_name(rv.ival)
        return rv.ival, functionname

    @staticmethod
    def IsPointer(ea, segments):
        return any(sgm.Contains(ea) for sgm in segments)

    @staticmethod
    def ReadPointer(ea):
        if idaapi.get_inf_structure().is_64bit():
            return idaapi.get_qword(ea)
        return idaapi.get_dword(ea)

    @staticmethod
    def GetStackAddr():
        rv = idaapi.regval_t()
        if idaapi.get_inf_structure().is_64bit():
            return idaapi.get_reg_val('RSP', rv).ival
        return idaapi.get_reg_val('ESP', rv).ival

    @staticmethod
    def GrabFunctionCode(ea):
        code = []
        func = idaapi.get_func(ea)
        while ea < func.end_ea:
            code.append([ea, idc.GetDisasm(ea)])
            ea = idc.next_head(ea)
        return code

    @staticmethod
    def Resume():
        idaapi.continue_process()
        event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        return IdaHelper.GetEA()
    
    @staticmethod
    def StepOver():
        idaapi.step_over()
        event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        return IdaHelper.GetEA()
    
    @staticmethod
    def StepInto():
        idaapi.step_into()
        event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        return IdaHelper.GetEA()

    @staticmethod
    def FindFunctionInTrace(functionname, traceevents):
        return next(
            (trace
             for trace in traceevents if trace.functionname == functionname),
            None)

    @staticmethod
    def Count(dictionary, key):
        if key in dictionary:
            dictionary[key] += 1
        else:
            dictionary[key] = 1
        return dictionary[key]

    @staticmethod
    def DiscoverSegments():
        # build list of segment and maybe sort them
        #ici regrouper les segments afin d'améliorer la rapiditié
        segments = []
        for s in idautils.Segments():
            start = idc.get_segm_start(s)
            end = idc.get_segm_end(s)
            name = idc.get_segm_name(s)
            segments.append(TraceCollection.Segment(start, end, name))
        return segments

    @staticmethod
    def AskConfigurationValues():
        c = idaapi.ask_long(GarbageValues.MAX_PARENT, "Number of parents to trace:")
        GarbageValues.MAX_PARENT if c is not None else GarbageValues.MAX_PARENT
        
        c =  idaapi.ask_long(GarbageValues.DISCOVERY_TRIES, "Number of discovery tries:")
        GarbageValues.DISCOVERY_TRIES = c if c is not None else GarbageValues.DISCOVERY_TRIES



class Watchdog():
    """_summary_
    Wathdog prevents the program from freezing. 
    This class is used in long loop like trace functions.
    """

    def __init__(self, timeout=60):
        self.timeout = timeout
        print("Watchdog started")

    def _Expire(self):
        raise Exception("Watchdog expired")

    def Start(self):
        self.started_time = time.time()

    def CheckExpired(self):
        if time.time() - self.started_time > self.timeout:
            self._Expire()
        return False


class TraceCollection:
    """_summary_
    Containes garbage class for collecting data from the memory and saving it.
    
    """

    class Segment:

        def __init__(self, start, end, name):
            self.start = start
            self.end = end
            self.name = name

        def Contains(self, addr) -> bool:
            return (addr >= self.start and addr <= self.end)

    class MemoryZone:
        """_summary_
        Represents a memory zone dumped because a register or a pointer found was pointing to it.
        """

        def __init__(self, regs_values):
            self.dump = {}
            self.regs_values = regs_values
        
        def Dump(self):
            self.DumpRegistersPoiters()

        def DumpAddr(self, addr, depth=0, size=50):
            """_summary_
            Dump a memory zone from an address. If inside the zone there is a pointer, 
            it will be dumped to by calling this function again.
            """
            if addr in self.dump or depth > 1:
                return
            self.dump[addr] = []
            incr = 8 if idaapi.get_inf_structure().is_64bit() else 4
            for i in range(size):
                try:
                    value = idaapi.get_qword(
                        addr + i * incr) if idaapi.get_inf_structure().is_64bit(
                        ) else idaapi.get_dword(addr + i * incr)
                    self.dump[addr].append(value)
                    self.DumpAddr(value, depth + 1, 30)
                except Exception as e:
                    print(e)
                    print(addr + i * incr)
                    break
                
                
        def DumpRegistersPoiters(self):
            for regname, regvalue in self.regs_values.items():
                self.DumpAddr(regvalue, size=50) 
                
                

    class EaEntry:
        """_summary_
        Single entry in the EA list. Each line of code is an entry.
        """

        def __init__(self, registers, variables, mem):
            self.registers = registers
            self.variables = variables
            self.mem = mem
            
        

    class FunctionEntry:
        """_summary_
        Wrapper for EaEntry enlarged with the function name.
        """

        def __init__(self, functionname):
            self.entries = OrderedDict()
            self.functionname = functionname

        def Clone(self):
            trace = TraceCollection.FunctionEntry(self.functionname)
            trace.entries = self.entries
            return trace

        def AddEntry(self, addr, registers, variables, segments):
            regs_values = IdaHelper.GetRegistersValues()
            memdump = TraceCollection.MemoryZone(regs_values)
            memdump.Dump()
            entry = TraceCollection.EaEntry(registers, variables, memdump)
            if addr not in self.entries:
                self.entries[addr] = [entry]  
            else:
                self.entries[addr].append(entry)
                
        def AddEntrySaved(self, addr, registers, variablessaved, memdumpsaved):
            memdump = TraceCollection.MemoryZone(registers)
            memdumpsaved = {int(k):v for k,v in memdumpsaved.items()}
            memdump.dump = memdumpsaved
            variables = TraceCollection.Variables()
            variables.extend([TraceCollection.VariableEntry.FromJSON(json) for json in variablessaved])
            entry = TraceCollection.EaEntry(registers, variables, memdump)
            if addr not in self.entries:
                self.entries[addr] = [entry]  
            else:
                self.entries[addr].append(entry)
            
           

    class VariableEntry:
        """_summary_
        Variable entry is saved into this class.
        """

        def __init__(self, name=None, defea=None, vdloc=None):
            self.name = name
            self.defea = defea
            self.vdloc = vdloc
            self.references = []

        def AppendReference(self, location):
            if location not in self.references:
                self.references.append(location)

        def DeleteReference(self, location):
            self.references.remove(location)
            
        def ToJSON(self):
            return json.dumps(self, default=lambda o: o.__dict__,  sort_keys=True, indent=4)

        @staticmethod
        def FromJSON(jsonString):
            variableentry = TraceCollection.VariableEntry()
            variableentry .__dict__ = json.loads(jsonString)
            return variableentry 
        
        
    class Variables(List):
        """_summary_
        Wrapper for VariableEntry , collections of variables.
        """

        def __init__(self):
            super().__init__()

        def AppendVariable(self, name, defea, vdloc):
            self.append(
                TraceCollection.VariableEntry(name, defea, vdloc))

        @staticmethod
        def FetchVariablesValues(varscollection):
            """_summary_
            Try to get variable values and save them into the variables_collection.
            """

            ea, _ = IdaHelper.GetEA()
            func = idaapi.get_func(ea)
            variables = None
            init = False

            if len(varscollection) == 0 or ea == func.start_ea:
                varscollection.append(
                    TraceCollection.Variables())
                init = True

            variables = varscollection[-1]
            if idc.print_insn_mnem(ea) in GarbageValues.ret:
                varscollection.pop()

            decompilation = idaapi.decompile(func.start_ea)
            if init:
                for var in decompilation.lvars:
                    if var.name != "":
                        variables.AppendVariable(var.name, var.defea, ida_hexrays.print_vdloc(var.location, int(var.width)))

            TraceCollection.Variables.Instanciate(ea, variables)
            return variables

        @staticmethod
        def Instanciate(ea, variables):
            for var in variables:
                # instantiate variables when they are created in the code
                if var.defea >= ea and ea < var.defea + 0x16 and len(
                        var.references) == 0:
                    var.AppendReference(var.vdloc)
                if str(idc.print_operand(ea, 0)) == str(var.vdloc):
                    var.AppendReference(idc.print_operand(ea, 0))
                for ref in var.references:
                    if idc.print_insn_mnem(ea) == "mov" and idc.print_operand(
                            ea, 1) == ref:
                        var.AppendReference(idc.print_operand(ea, 1))
                        break

    @staticmethod
    def LoadTrace():
        file = easygui.fileopenbox(filetypes=["*.json"])
        last_trace_index = -1
        if not file:
            return
        f = open(file, 'r')
        content = json.load(f)
        traceevents = []
        last_invoke = content["last_invoke"]
        timestotrace = content["timestotrace"]
        for entry in content["trace"] :
            trace_index = entry["trace_index"]
            if trace_index > last_trace_index:
                last_trace_index = trace_index
                functraced = TraceCollection.FunctionEntry(
                    entry["functionname"])
                traceevents.append(functraced)
            entry_content = entry["content"]
            ea = int(entry["ea"])
            registers = entry_content["registers"]
            variables = entry_content["variables"]
            memdump = entry_content["memdump"]
            functraced.AddEntrySaved(ea, registers, variables, memdump)
        f.close()
        return traceevents, last_invoke, timestotrace

    @staticmethod
    def SaveTrace(traceevents, last_invoke, timestotrace):
        file = easygui.filesavebox("Save file",
                                   default='trace',
                                   filetypes=['*.json'])
        content = {}
        file = open(file, 'w')
        content["last_invoke"] = last_invoke
        content["timestotrace"] = timestotrace
        content["trace"] = []
        for i, trace in enumerate(traceevents):
            for k, entry in trace.entries.items():
                for j in range(len(entry)):
                    registersentry = entry[j].registers
                    registers = registersentry 
                    variables = [variable.ToJSON() for variable in entry[j].variables]
                    content["trace"].append({
                        "ea": k,
                        "trace_index": i,
                        "functionname": trace.functionname,
                        "content": {
                            "registers": registers,
                            "variables": variables,
                            "memdump": entry[j].mem.dump
                        }
                    })
        json.dump(content, file)
        file.close()


class UI(PluginForm):
    """_summary_
    This class manages the UI of the plugin.
    """

    def AttachTracer(self, valuetracer):
        self.valuetracer = valuetracer
        self.stack_pointer_printed = {}

    def OnCreate(self, form):
        print("Create ui form")
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        print("PopulateForm")
        # Create layout
        layout = QtWidgets.QHBoxLayout()
        self.callsW = QtWidgets.QListWidget()
        self.callsW.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection)
        self.callsW.currentItemChanged.connect(self.ShowCode)
        self.callsW.setFixedWidth(200)
        self.codeW = QtWidgets.QListWidget()
        self.codeW.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection)
        self.codeW.currentItemChanged.connect(self.ShowTrace)
        self.codeW.setFixedWidth(300)
        self.dump = QtWidgets.QHBoxLayout()
        self.dataW = QtWidgets.QListWidget()
        self.dataW.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection)
        self.dataW.currentItemChanged.connect(self.ShowMemoryDump)
        self.dataW.setFixedWidth(400)
        self.stackL = QtWidgets.QListWidget()
        self.stackL.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection)
        self.stackL.setFont(QtGui.QFont('Consolas', 9))
        self.dataW.setFixedWidth(300)
        self.stackL.currentItemChanged.connect(self.ShowStackDumpedPointer)
        self.widget = QtWidgets.QWidget()
        self.widget.setFixedWidth(150)
        self.restartBtn = QtWidgets.QPushButton('Reset', self.widget)
        self.restartBtn.clicked.connect(self.valuetracer.ActionReset)
        self.restartBtn.setGeometry(0, 50, 140, 40)
        self.cleanBtn = QtWidgets.QPushButton('Clean bpts', self.widget)
        self.cleanBtn.setGeometry(0, 250, 140, 40)
        self.cleanBtn.clicked.connect(self.valuetracer.CleanBreakpoints)
        self.saveBtn = QtWidgets.QPushButton('Save', self.widget)
        self.saveBtn.clicked.connect(self.valuetracer.Save)
        self.saveBtn.setGeometry(0, 300, 140, 40)
        self.traceBtnGlobal = QtWidgets.QPushButton('Function Tracing', self.widget)
        self.traceBtnGlobal.setGeometry(0, 0, 140, 40)
        self.traceBtnGlobal.clicked.connect(self.valuetracer.ActionGlobalTrace)
        self.traceBtnChirugical = QtWidgets.QPushButton('Chirugical Tracing',
                                                   self.widget)
        self.traceBtnChirugical.setGeometry(0, 100, 140, 40)
        self.traceBtnChirugical.clicked.connect(
            self.valuetracer.ActionChirugicalTrace)
        self.loadBtn = QtWidgets.QPushButton('Load', self.widget)
        self.loadBtn.setGeometry(0, 350, 140, 40)
        self.loadBtn.clicked.connect(self.valuetracer.Load)
        self.stepOverBtn = QtWidgets.QPushButton('Step Over', self.widget)
        self.stepOverBtn.setGeometry(0, 150, 140, 40)
        self.stepOverBtn.clicked.connect(self.valuetracer.ActionStepOver)
        self.stepIntoBtn = QtWidgets.QPushButton('Step Into', self.widget)
        self.stepIntoBtn.setGeometry(0, 200, 140, 40)
        self.stepIntoBtn.clicked.connect(self.valuetracer.ActionStepInto)
        self.dump.addWidget(self.dataW)
        self.dump.addWidget(self.stackL)
        layout.addWidget(self.callsW)
        layout.addWidget(self.codeW)
        layout.addLayout(self.dump)
        layout.addWidget(self.widget)
        
         # make our created layout the dialogs layout
        self.parent.setLayout(layout)

    def AddCall(self, item):
        self.callsW.addItem(item)

    def AddCode(self, item):
        self.codeW.addItem(item)

    def AddData(self, item):
        self.dataW.addItem(item)
        
    def AddDump(self, item):
        self.stackL.addItem(item)

    def Reset(self):
        self.dataW.clear()
        self.callsW.clear()
        self.codeW.clear()
        self.stackL.clear()
        self.stack_pointer_printed = {}
        with contextlib.suppress(Exception):
            self.callsW.setCurrentRow(0)
            self.codeW.setCurrentRow(0)
            
        
            

    def ShowMemoryDump(self, traceevents):
        """_summary_
        Show the memory dump of the current instruction.
        """
        self.stackL.clear()
        try:
            functionname = self.callsW.currentItem().text()
            addr = self.dataW.currentItem().text()
            ea = int(self.codeW.currentItem().text().split(" ")[0], 16)
        except AttributeError:
            functionname = self.dataW.item(0).text()
            addr = self.dataW.item(0).text()
            ea = int(self.codeW.item(0).text().split(" ")[0], 16)
        zfill = 16 if idaapi.get_inf_structure().is_64bit() else 8
        addr = int(addr.split(" ")[-1], 16)
        idaapi.jumpto(ea)
        indexcode = self.codeW.currentRow()
        # addr, ea, functionname, self.valuetracer.traceevents, index, self.valuetracer.timestotrace
        params = {"addr": addr, "ea": ea, "functionname": functionname, "traceevents": self.valuetracer.traceevents, "index": indexcode, "timestotrace": self.valuetracer.timestotrace}
        for dump in GarbageHelper.FormatDataDump(**params):
            self.AddDump(dump)

    def ShowCode(self):
        """_summary_
        Show the code of the function the user selected in the GUI
        """
        self.codeW.clear()
        code = []
        print(self.valuetracer.last_invoke)
        if self.valuetracer.last_invoke == Invoke.CHIRUGICAL_TRACER:
            for trace in self.valuetracer.traceevents:
                for ea, entry in trace.entries.items():
                    code.extend([ea, idc.GetDisasm(ea)] for _ in entry)
        else:
            funcName = self.callsW.currentItem().text()
            ea = idc.get_name_ea_simple(funcName)
            code = IdaHelper.GrabFunctionCode(ea)
        self._ShowCode(code)
            

    def _ShowCode(self, code):
        for code_entry in code:
            ea = code_entry[0]
            functionname = idc.get_func_name(ea)
            string = hex(ea) + " " * 4 + code_entry[1]
            self.AddCode(string)
            line = self.codeW.item(self.codeW.count() - 1)
            if self.valuetracer.last_invoke == Invoke.GLOBAL_TRACER:
                if (ida_dbg.get_bpt(code_entry[0], ida_dbg.bpt_t())):
                    line.setBackground(QtGui.QColor(102, 0, 12))
                else:
                    line.setBackground(QtGui.QColor(102, 105, 110))
            for trace in self.valuetracer.traceevents:
                if trace.functionname != functionname:
                    continue
                for k, v in trace.entries.items():
                    if k != ea:
                        continue
                    line.setBackground(QtGui.QColor(0, 102, 12))
                    break

    def ShowTrace(self):
        """_summary_
        Show the trace in the GUI
        """
        self.dataW.clear()
        try:
            functionname = self.callsW.currentItem().text()
            ea = int(self.codeW.currentItem().text().split(" ")[0], 16)
        except AttributeError:
            functionname = self.callsW.item(0).text()
            ea = int(self.codeW.item(0).text().split(" ")[0], 16)
        idaapi.jumpto(ea)
        for trace in self.valuetracer.traceevents:
            if trace.functionname != functionname:
                continue
            for k, entry in trace.entries.items():
                if k != ea:
                    continue
                
                # special case for chirugical tracing
                index = 0 if self.valuetracer.last_invoke != Invoke.CHIRUGICAL_TRACER else self.codeW.currentRow()%self.valuetracer.timestotrace
                if index > len(entry) - 1:
                    raise Exception("Index out of range")
                    
                for regname, regvalue in GarbageHelper.ConvertRegistersValues(
                        entry[index].registers).items():
                    self.AddData(f"{regname}: {regvalue}")
                for _ , vstring in GarbageHelper.ConvertVariablesValues(
                        entry[index].variables, entry[index].registers).items():
                    self.AddData(f"{vstring}")
                break

    def ShowStackDumpedPointer(self):
        """_summary_
        When we click on a valid pointer into the memory dump, we trigger this function that show the memory dump
        of the pointed address
        """
        stack = self.stackL.currentItem().text()
        item = self.stackL.findItems(stack, QtCore.Qt.MatchExactly)[0]
        index = self.stackL.indexFromItem(item).row()
        addr = int(stack.split(" ")[0], 16)
        # if index in self.stack_pointer_printed:
        #     return
        self.stack_pointer_printed[index] = True
        ea = int(self.codeW.currentItem().text().split(" ")[0], 16)
        functionname = self.callsW.currentItem().text()
        indexcode = self.codeW.currentRow()
        params = {"addr": addr, "ea": ea, "functionname": functionname, "traceevents": self.valuetracer.traceevents, "index": indexcode, "timestotrace": self.valuetracer.timestotrace}
        for dump in GarbageHelper.FormatDataDump(**params):
            self.stackL.insertItem(index + 1, " " * 8 + dump)

    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        with contextlib.suppress(Exception):
            self.valuetracer.CleanBreakpoints()
            idaapi.clear_trace()




class SuperTracer():

    flags = 0
    comment = "Plugin for improve the reverse engineering speed of IDA when you want tog focus on a Chirugical part of the code"
    help = "See https://github.com/"
    wanted_name = "SuperTracer"
    


    def __init__(self):
        super().__init__()
        self.discoveredfuncs = []
        self.bpts = []
        self.varscollection = []
        self.traceevents = []
        self.segments = []
        self.prevfuncea = 0
        self.last_invoke = None
        self.watchDog = Watchdog()
        self.timestotrace = 1

    def Save(self):
        """_summary_
        Save the current state of the plugin
        """
        TraceCollection.SaveTrace(self.traceevents, self.last_invoke, self.timestotrace)
        
        
    def AttachUi(self, UI):
        """_summary_
        Attach the UI to the plugin
        """
        self.UI = UI

    def Load(self):
        """_summary_
        Load the saved state of the plugin
        """
        self.Reset()
        self.traceevents, self.last_invoke, self.timestotrace = TraceCollection.LoadTrace()
        for trace in self.traceevents:
            self.UI.AddCall(trace.functionname)

    def Reset(self):
        self.UI.Reset()
        for ea in self.bpts:
            idaapi.del_bpt(ea)
        self.bpts = []
        self.varscollection = []
        self.prevfuncea = 0
        self.traceevents = []
        
    def PrepareTrace(func):
        def wrap(self, *args, **kw):
            self.timestotrace = 1
            if self.last_invoke == Invoke.CHIRUGICAL_TRACER:
                self.Reset()
            return func(self)
        return wrap
    
    def ActionReset(self):
        self.Reset()

    def ActionGlobalTrace(self):
        """_summary_
        Trrigger the global trace action
        """
        self.Reset()
        IdaHelper.Resume()
        self.last_invoke = Invoke.GLOBAL_TRACER
        self.SetupGlobalTrace()
        self.GlobalTrace()
        print("End Global Trace")
        self.CleanBreakpoints()

    def ActionChirugicalTrace(self):
        """_summary_
        Trrigger the Chirugical trace action
        """
        self.Reset()
        IdaHelper.Resume()
        self.CleanBreakpoints()
        self.last_invoke = Invoke.CHIRUGICAL_TRACER
        self.timestotrace = idaapi.ask_long(10, "Number of times to trace:")
        self.ChirugicalTrace()
        
    @PrepareTrace
    def ActionStepOver(self):
        """_summary_
        Trigger the step over action
        """
        self.StepOverTrace()
        self.last_invoke = Invoke.GLOBAL_TRACER
        self.UI.ShowCode()
        
        
    @PrepareTrace
    def ActionStepInto(self):
        """_summary_
        Trigger the step into action 
        """
        self.last_invoke = Invoke.GLOBAL_TRACER
        self.StepIntoTrace()
        self.UI.ShowCode()
        
    def CleanBreakpoints(self):
        """_summary_
        Remove all breakpoints
        """
        with contextlib.suppress(Exception):
            bptMaster = idc.get_name_ea_simple(self.main_function)
            ida_dbg.enable_bpt(bptMaster, True)
        for ea in self.bpts:
            if ea != bptMaster:
                idaapi.del_bpt(ea)
        self.bpts = []

    def SetBreakpointsOnReturns(self, ea):
        """
        Set a breakpoint on the return address of the function
        """
        func = idaapi.get_func(ea)
        ea = func.start_ea
        while ea < func.end_ea:
            QtWidgets.QApplication.processEvents()
            if idc.print_insn_mnem(ea) in GarbageValues.ret:
                if ea not in self.bpts:
                    self.bpts.append(ea)
                    idaapi.add_bpt(ea, idaapi.BPT_SOFT)
                else:
                    idaapi.enable_bpt(ea)
            ea = idc.next_head(ea)

    def DiscoverParents(self):
        """_summary_
        Set breakpoints on the return addresses of the functions to discover their parents
        Repeat this process by using the DISCOVER_PARENTS flag and the DISCOVERY_TRIES flag
        """
        for _ in range(GarbageValues.DISCOVERY_TRIES):
            # disable all breakpoints added by this plugin
            for self.ea in self.bpts:
                idaapi.disable_bpt(self.ea)
            # run until we hit the user defined function
            idaapi.continue_process()
            # continue until we got a breakpoint (retn)
            for _ in range(GarbageValues.MAX_PARENT):
                self.SetBreakpointsOnReturns(self.ea)
                idaapi.continue_process()
                event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
                idaapi.step_into()
                event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
                self.ea, functionname = IdaHelper.GetEA()
                self.discoveredfuncs.append(functionname)

        # # delete all breakpoints added by this plugin
        self.CleanBreakpoints()

    def DiscoverChildren(self):
        """_summary_
        Discover the children of the main function
        """
        ea = idc.get_name_ea_simple(self.main_function)
        for line in idautils.FuncItems(ea):
            print(idc.print_insn_mnem(line), idc.print_operand(line, 0) )
            if idc.print_insn_mnem(line) == "call":
                functionname = idc.print_operand(line, 0)
                self.discoveredfuncs.append(functionname)
                
                
                
        print("end of children discovery")

    def SetBreakpointsIntoDiscoveredFunctions(self):
        """_summary_
        Set breakpoints on the discovered functions
        """
        for functionname in self.discoveredfuncs:
            try:
                self.ea = idc.get_name_ea_simple(functionname)
                func = idaapi.get_func(self.ea)
                while self.ea < func.end_ea:
                    idaapi.add_bpt(self.ea, idaapi.BPT_SOFT)
                    self.bpts.append(self.ea)
                    self.ea = idc.next_head(self.ea)
            except AttributeError:
                print(f"Function not found: {functionname}")

    def SetupGlobalTrace(self):
        """_summary_
        Wrapper for function discovering and breakpoint setting
        """
        self.ea, functionname = IdaHelper.GetEA()
        self.main_function = functionname
        print(f"Main function: {functionname}")
        if functionname not in self.discoveredfuncs:
            self.discoveredfuncs.append(functionname)
        IdaHelper.AskConfigurationValues()
        self.DiscoverParents()
        self.DiscoverChildren()
        self.discoveredfuncs = list(set(self.discoveredfuncs))
        self.SetBreakpointsIntoDiscoveredFunctions()

    def InstantiateTrace(self, ea, functionname):
        """_summary_
        Create a new trace event (entering in a new function)
        """
        trace = TraceCollection.FunctionEntry(functionname)
        self.traceevents.append(trace)
        self.UI.AddCall(functionname)
        return trace

    def Trace(self):
        """_summary_
        Continue the process and manage the trace events
        """
        self.watchDog.CheckExpired()
        ea, functionname = IdaHelper.Resume()
        ida_dbg.disable_bpt(ea)
        self._Trace(ea, functionname)
        
    def StepOverTrace(self):
        ea, functionname = IdaHelper.StepOver()
        self._Trace(ea, functionname)
        
    def StepIntoTrace(self):
        ea, functionname = IdaHelper.StepInto()
        self._Trace(ea, functionname)
        
        
    def _Trace(self, ea, functionname):
        idaapi.refresh_idaview_anyway()
        QtWidgets.QApplication.processEvents()
        idaapi.jumpto(ea)
        trace = IdaHelper.FindFunctionInTrace(functionname,
                                                   self.traceevents)
        trace = self.InstantiateTrace(ea,
                                      functionname) if trace is None else trace
        trace.AddEntry(
            ea, IdaHelper.GetRegistersValues(),
            TraceCollection.Variables.FetchVariablesValues(
                self.varscollection), self.segments)

    def GlobalTrace(self):
        """_summary_
        This function is responsible for the global trace action. 
        """
       
        self.watchDog.Start()
        # trace parents and main function ->  get down
        while True:
            self.Trace()
            if IdaHelper.GetEA()[1] != self.main_function:
                break
        #  -> get up
        for _ in range(len(self.traceevents)):
            ea, functionname = IdaHelper.GetEA()
            self.SetBreakpointsOnReturns(ea)
            while True:
                QtWidgets.QApplication.processEvents()
                self.watchDog.CheckExpired()
                if idc.print_insn_mnem(ea) in GarbageValues.ret:
                    ida_dbg.step_over()
                    event = ida_dbg.wait_for_next_event(
                        ida_dbg.WFNE_SUSP, -1)
                    break
                ea, functionname = IdaHelper.GetEA()
                self.Trace()
            self.UI.AddCall(functionname)
        ida_dbg.request_enable_insn_trace(False)
        
    def ChirugicalTrace(self):
        """_summary_
        This function is responsible for the Chirugical trace action.
        """
        try:
            self.watchDog.Start()
            ea_passed = {}
            ea, functionname = IdaHelper.GetEA()
            while IdaHelper.Count(ea_passed, ea) <= self.timestotrace:
                ea, functionname = IdaHelper.Resume()
                self._Trace(ea, functionname)
        except Exception as e:
            print(e)

    def ActionRestartTrace(self):
        self.Reset()
        with contextlib.suppress(Exception):
            self.last_invoke()

    def _Start(self):
        if self.UI is None:
            raise Exception("UI is not initialized")
        print("Starting trace")
        self.segments = IdaHelper.DiscoverSegments()
        self.Reset()
        
        
class Invoke(IntEnum):
    GLOBAL_TRACER = 1
    CHIRUGICAL_TRACER = 2
        
ui, tracer = UI(), SuperTracer()

ui.AttachTracer(tracer)
tracer.AttachUi(ui)

for i in range(10):
    try:
        ui.Show(f"EasyRe - {hex(i)}")
        ui.AddCode("Message de base")  # disable all breakpoints
        break
    except Exception as e:
        logging.error(e)
ui.valuetracer._Start()
