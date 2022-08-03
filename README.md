# EasyRe
IDA Python3 script that's make you re life easier. It allows to trace and saved code/memory thats you selected, then browse the trace.

## How to used

[![demo](https://img.youtube.com/vi/rFiICyep3hE/0.jpg)](https://youtu.be/rFiICyep3hE)

### Function Tracing
  
  This functionality aims to hook the function code, but also discover parents. It will save the trace of the parents, the current function and the children of the function, and dump data associated. Best choice to understand a function.
  
 To use it you must place a single breakpoints at the start of the function that's you want to analyse and hit that breakpoint with IDA. Then launch the tracing.

- **DISCOVERY_TRIES** is a param that will control the number of time the code resume and hits again you breakpoint. Increase that number to discover more parents functions
- **MAX_PARENTS** is the number of parents to discover ( considers as a tree)


### Chirugical Tracing
   But breakpoits on the address you want to monitor, select the number of time you want to trace the code and launch the trace. It will run the program until all 
   breakpoints set where hits the number of time you selected.
   
   
### StepOver and StepInto
   As the name suggest go to the next instruction and save the data
   
   
### Load And Save
  The script has the capacity to save the trace in order to load it the next time you want to compare it.
