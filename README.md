# EasyRe X86-X64 Plugin
IDA Python3 plugin to make your runtime analysis easier. It allows you to trace the code you select, then browse the trace, see registers, values and memory associated with the instructions saved by the trace. It makes it easy to compare data given to specific parts of the code between different calls.

**New feature : Windows API hooking ? Try it !**

## Usage

Youtube video link (old version) : 

[![demo](https://i.ibb.co/Wvwnt2N/Image1.png)](https://youtu.be/rFiICyep3hE)


### Function Tracing
  
  This functionality aims to hook the function code, but also discover parents. It will save the trace of the parents, the current function and the children of the function, and dump the associated data. Best choice to understand a function.
  
 To use it you must place a single breakpoint at the start of the function you want to analyze and hit that breakpoint with IDA. Then launch the tracing.

- **DISCOVERY_TRIES** controls the number of times the code resumes and hits the breakpoint again. Increase that number to discover more parents functions.
- **MAX_PARENTS** is the number of parents to discover (considers as a tree)


### Chirugical Tracing
   Put breakpoints on the addresses you want to monitor, select the number of times you want to trace the code and launch the trace. It will run the program until all 
   breakpoints are hit the chosen number of times.
   
   
### StepOver, StepInto, Resume
   Go to the next instruction and save the data.
   
   
### Load And Save
  The plugin can save the trace in order to load it the next time you want to work with it.
