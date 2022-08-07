# EasyRe X86-X64 Plugin
IDA Python3 Plugin to make your RE life easier. Trace execution and save code/memory for detailed exploration. It allow in a easy way to compare data given to specific part of the code between different calls. 

**New feature : Windows API hooking ? Try it !**

## How to used

Youtube video link (old version) : 

[![demo](https://i.ibb.co/Wvwnt2N/Image1.png)](https://youtu.be/rFiICyep3hE)

### Shortcut

crtl+alt+S

### Function Tracing
  
  Function Tracing functionality aims to but breakpoints one the whole code of a function in order to register each steps. Te goal is to save all in order to understand what's going on thanks to the trace explorer integrated in this plugin
  
 In order to use it you must place **a single breakpoints** at the start of the function that's you want to analyse and hit that breakpoint with IDA, then launch the tracing.
 
 When you will click on the button to trigger this item, a prompt will ask for two variables:

  - Var **Discovery tries** is a direct control to discover the functions that call the one you're currently in. The technique to discover the parents is to execute the function and then, when the EIP is on a ret instruction, we will register the function that called it. And we can repeat this step several times to discover parent ofs the parent, etc ...
  
  - Var **Max parents** is the variable that will control the number of parents of the function. The more we increase, the more we will go up in the call stack, and then trace the calls and the set of operations performed in the parent functions


### Surgical Tracing
   In case you only want to monitor specific places in the code, this option is the right choice. It allows you to put breakpoints at different places in the code, and then choose the number of times you want to pass over them. This allows us to compare the values of the registers and the stack between several passes.
   
   
### StepOver, StepInto, Resume
   As the name suggest, simply go to the next instruction and register the data in the trace
   
   
### Load And Save
  The plugin has the capacity to save the trace in order to load it the next time you need it 
