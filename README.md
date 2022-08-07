# EasyRe x86-x64 plugin

![tags](https://img.shields.io/badge/tags-%20ida%20ida--pro%2C%20ida--plugin%2C%20idapython-blue) ![version](https://img.shields.io/badge/version-0.2-yellowgreen)

IDA Python 3 plug-in to make your RE life easier. Trace execution and save code/memory for detailed exploration. It allow in a easy way to compare data given to specific part of the code between different calls. 

## How to used

You tube video link (old version) : 

[![demo](https://i.ibb.co/Wvwnt2N/Image1.png)](https://youtu.be/rFiICyep3hE)

------

## Shortcut :

`crtl+alt+S`

## Functionality :

### Function Tracing

  Function Tracing functionality aims to but breakpoints one the whole code of a function in order to register each steps. Te goal is to save all in order to understand what's going on thanks to the trace explorer integrated in this plug-in.

 In order to use it you must place **a single breakpoints** at the start of the function that's you want to analyses and hit that breakpoint with IDA, then launch the tracing.

 When you will click on the button to trigger this item, a prompt will ask for two variables:

  - >  Variable **Discovery tries** is a direct control to discover the functions that call the one you're currently in. The technique to discover the parents is to execute the function and then, when we hit a  *ret* instruction, we will register the function that called it; and we can repeat this step several times to discover parent of the parent, etc ...
  
  - > Variable **Max parents** is the variable that will control the number of parents of the function. The more we increase, the more we will go up in the call stack, and then trace the calls and the set of operations performed in the parent functions up to the one we focused on.


### Surgical Tracing
   In case you only want to monitor specific places in the code, this option is the right choice. It allows you to put breakpoints at different places in the code, and then choose the number of times you want to pass over them. This allows us to compare the values of the registers and the stack between several passes.


### Step Over,  Step Into,  Resume
   As the name suggest, simply go to the next instruction and register the data in the current trace.


### Load And Save
  The plug in has the capacity to save the trace in order to load it the next time you need it. 

### Windows  API hook

If you are tired of placing breakpoints on windows functions that are entry points for the kernel and are often used by malware, here is a feature that should be of interest to you. It will automatically place breakpoints on a number of system functions, even if they are not in the imports, in order to make the reverse easier



