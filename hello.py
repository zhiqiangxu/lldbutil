# -*- coding: utf-8 -*-
import lldb
import logging
logger = logging.getLogger('myapp')
if not logger.handlers:
    hdlr = logging.FileHandler('/tmp/myapp.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

# command script import /Users/gumichina01/Desktop/develop/projects/lldbutil/hello.py
def doLog(msg):
    logger.info(msg)
    logger.handlers[0].flush()


def callback_delegate(a, b, c):
    lldb.debugger.HandleCommand("""exp -d run-target --
                                LOGIN_URL = "http://login.bf.gumichina.com/loginserver/getServerList/login.php";
                                GLOBAL_ID = newString("100010");
                                OS = newString("1");
                                PLATFORM = newString("2");
                                CHANNEL_ID = newString("999999");
                                DEVICE_ID = "xuzhiqiang";
                                CHANNEL_TOKEN = "abc";
                           """)
    """
    lldb.debugger.HandleCommand('watchpoint set expression -w write -- GLOBAL_ID')
    lldb.debugger.HandleCommand('watchpoint set expression -w write -- OS')
    lldb.debugger.HandleCommand('watchpoint set expression -w write -- CHANNEL_ID')
    """
    lldb.debugger.HandleCommand('continue')

    return True

def switch(debugger, command, result, dict):
    target = lldb.debugger.GetSelectedTarget()
    index = target.GetNumBreakpoints() + 1


    cmd = 'b AppDelegate::applicationDidFinishLaunching'
    doLog(cmd)
    debugger.HandleCommand(cmd)
    cmd = 'breakpoint command add -s python %s -F %s' % (index, 'hello.callback_delegate')
    doLog(cmd)
    debugger.HandleCommand(cmd)

    return False

def say_hello(debugger, command, result, d):
    #debugger.HandleCommand('exp -u false -d run-target -- s_SharedDirector.getRunningScene()')

    """
        target = lldb.debugger.GetSelectedTarget()
        value = evaluateExpressionValue('s_SharedDirector.getRunningScene()')
        print "{} breakpoints\n".format(target.GetNumBreakpoints())
        print value.type.name
        print value
        print repr(value)
    """
    debugger.HandleCommand('exp  -u true -- (void)mylog(0)')

def find_cstr(debugger, command, result, d):
    exp = '''
        char *begin = (char *)%s;
        while(*begin != 0)
            begin = begin - 1;
        begin + 1;
'''
    frame = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
    expr_sbvalue = frame.EvaluateExpression (exp % command, lldb.eDynamicCanRunTarget)
    if expr_sbvalue.error.Success():
        match_value = lldb.value(expr_sbvalue)
        print match_value

def ptype(debugger, command, result, d):
    frame = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
    dv = frame.EvaluateExpression('(void*)%s' % command, lldb.eDynamicCanRunTarget)#.GetDynamicValue(lldb.eDynamicCanRunTarget)
    print dv.type.name

    target = lldb.debugger.GetSelectedTarget()
    so_addr = target.ResolveLoadAddress (int(command, 16))
    print so_addr.IsValid()
    sym_ctx = target.ResolveSymbolContextForAddress (so_addr, lldb.eSymbolContextSymbol)
    print sym_ctx
    symbol = sym_ctx.GetSymbol()
    print symbol
    print symbol.GetName()
    print symbol.GetType()

    print '-----'
    symbolicator = lldb.utils.symbolication.Symbolicator()
    symbolicator.target = lldb.debugger.GetSelectedTarget()
    frames = symbolicator.symbolicate(int(command, 16))
    print frames

    print '----'
    print target.FindFirstType('SpriteButton')


def evaluateExpressionValue(expression, printErrors=True):
  # lldb.frame is supposed to contain the right frame, but it doesnt :/ so do the dance
  frame = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
  value = frame.EvaluateExpression(expression, lldb.eDynamicCanRunTarget)
  if printErrors and value.GetError() is not None and str(value.GetError()) != 'success':
    print value.GetError()
  return value

def __lldb_init_module (debugger, dict):

  debugger.HandleCommand('command script add -f hello.say_hello hello')
  debugger.HandleCommand('command script add -f hello.switch switch')
  debugger.HandleCommand('command script add -f hello.find_cstr find_cstr')
  debugger.HandleCommand('command script add -f hello.ptype ptype')

