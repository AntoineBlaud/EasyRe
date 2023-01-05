# EasyRe plugin

![tags](https://img.shields.io/badge/tags-%20ida%20ida--pro%2C%20ida--plugin%2C%20idapython-blue) ![arch](https://img.shields.io/badge/arch-x86/x64-lightgrey) ![version](https://img.shields.io/badge/version-0.2-yellowgreen)

IDA Python 3 plug-in to make your RE life easier. Trace execution and save code/memory for detailed exploration. It allow in a easy way to compare data given to specific part of the code between different calls. 

## NEW 
Go checkout [frida-utltimap](https://github.com/AntoineBlaud/frida-ultimap).

## Usage

You tube video link (old version) : 

[![demo](https://i.ibb.co/Wvwnt2N/Image1.png)](https://youtu.be/rFiICyep3hE)

------

## Installation :
```pip3 install idna easygui```

## Shortcut :

`Open the plugin : crtl+shift+u`

## Usage :

### Function Tracing

  Function tracing puts breakpoints on the whole code of a function and  its direct children in order to register each step. The goal is to  capture the whole trace in order to understand what's going on thanks to the trace explorer integrated in this plug-in.

 **Important:** In order to use it you must place a single breakpoint at the  start of the function you want to analyze and hit that breakpoint with  IDA, then launch the tracing.


### Surgical Tracing
   In case you only want to monitor specific places in the code, this option is the right choice. It allows you to put breakpoints at different places in the code, and then choose the number of times you want to pass over them. This allows us to compare the values of the registers and the stack between several passes.


### Step Over,  Step Into,  Resume
   As the name suggest, simply go to the next instruction and register the data in the current trace.


### Load And Save
  The plug-in has the capacity to save the trace in order to load it the next time you need it. 

### Windows  API hook

  If you are tired of placing breakpoints on windows functions that are entry points for the kernel and are often used by malware, here is a feature that should be of interest to you. It will automatically place breakpoints on a number of system functions, even if they are not in the imports, in order to make reversing easier.

## Extra Note:

Some improvements will come in the next months, like an accurate parent tracing.



