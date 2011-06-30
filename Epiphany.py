from Tkinter import *
from pydbg import *
import utils
import sys
import pefile
import time, threading, random, Queue
import Tix
import cl2
from pydbg.defines import *
from ScrolledText import ScrolledText
import subprocess

class MyApp(object):                         ### (1)
    def __init__(self, myParent,q):      ### (1a)
        self.parent = myParent
        self.process = ""
        self.queue = q
        self.select = ""
        self.selectInput = ""
        self.procinfo = []
        self.hook_address = []
        self.frame2 = ""
        self.pid = 0
        self.cl = ""
        self.on = True
        self.on2 = True
        self.dbg = pydbg()
        self.bp = []
        self.input = []
        self.params = {}
        self.myContainer1 = Frame(myParent,width=500,height=500)
        self.myContainer1.pack(fill=X, padx=5, pady=5)
        self.button1 = Button(self.myContainer1, width=20) 
        self.button1["text"]= "Attach!"     
        self.button1["background"] = "green"
        self.button1.bind("<Button-1>", self.button1Click)
        self.button1.bind("<Return>", self.button1Click)
        if self.button1["state"] == NORMAL:
            self.button1["text"]= "Attach!"
        else:
            self.button1["text"]= "Detach!"
        self.button1.pack(side=LEFT)                           
            
        self.button2 = Button(self.myContainer1, width=20)
        self.button2["text"]= "Hook"
        self.button2.bind("<Button-1>", self.button2Click)
        self.button2.bind("<Return>", self.button2Click)
        self.button2.pack(side=LEFT)                           
        
        self.button3 = Button(self.myContainer1, width=20)
        self.button3["text"]= "Memory BP"
        self.button3.pack(side=LEFT)                           

        self.button4 = Button(self.myContainer1, width=20)
        self.button4["text"]= "User Input"
        self.button4.bind("<Button-1>", self.inputClick)
        self.button4.bind("<Return>", self.inputClick)
        self.button4.pack(side=LEFT)  

        self.button5 = Button(self.myContainer1, width=20)
        self.button5["text"]= "Go!"
        self.button5.bind("<Button-1>", self.goClick)
        self.button5.bind("<Return>", self.goClick)
        self.button5.pack(side=LEFT)                           
        
        self.modlists={}
        self.textbox = None
        self.listbox = None
        self.cl = None
        self.count = 0
        self.data = ""
        self.trigger = True
        self.thread1 = None
        self.e = ""
        self.TraceData = []
        #self.update_clock()

    def cb_checked(self):
        print self.cb_v.get()
    
    def get_module_function(self, path):
        #execpath = "C:\Program Files\SAP\FrontEnd\SAPgui\saplogon.exe"
        execpath = path
        pe=pefile.PE(execpath)
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print entry.dll
                l = []
                t=[]
                k = 0
                for imp in entry.imports:
                    a = imp.name
                    if a == None:
                        a = str(a)+str(k)
                        k+=1
                    t = [imp.address, a, False]
                    l.append(t)
                self.modlists[entry.dll]= l



    def button1Click(self, event):
        #if not self.frame2:
        self.frame2 = Frame(self.parent, width=500,height=500)
        self.frame2.pack(fill=X, padx=5, pady=5)
        scroll = Scrollbar(self.frame2, orient=VERTICAL)
        self.select = Listbox(self.frame2, yscrollcommand=scroll.set, height=25)
        for (pid, name) in self.dbg.enumerate_processes():
            #x = mcb(top, name, pid, self)
            self.procinfo.append((pid,name))
            self.select.insert(END,name)
        scroll.config (command=self.select.yview)
        scroll.pack(side=RIGHT, fill=Y)
        self.select.pack(side=LEFT,  fill=BOTH, expand=1)
        b = Button(self.frame2, text="Select")
        b.bind("<Button-1>", self.button3Click)
        b.pack(side=BOTTOM)
        

    def button2Click(self, event):
        print self.process, self.pid
        path = subprocess.Popen(["pid2path", str(self.pid)], stdout=subprocess.PIPE).communicate()[0]
        print path
        self.get_module_function(path)
        #top = Toplevel()
        #self.get_module_function(pa)
        a = "CL"
        i = 0
        print "\n============*****======"
        print self.modlists
        print self.bp
        self.frame2 = Frame(self.parent, width=500, height=500)
        self.frame2.pack(fill=X, padx=5, pady=5)
        #swin = Tix.ScrolledWindow(self.frame2, width=500, height=500)
        #swin.pack()
        self.cl = Tix.CheckList(self.frame2, browsecmd=self.selectItem, height =300, width = 300)
        self.cl.pack()
        b = Button(self.frame2, text="OK")
        b.bind("<Button-1>", self.button4Click)
        b.pack(side=BOTTOM)
        for key in self.modlists:   
            #print key
            a = key.split('.')[0]
            #a = a + str(i)      
            self.cl.hlist.add(a, text=str(key))
            self.cl.setstatus(a, "off")
            #i+=1
            l = self.modlists[key]
            #k = 0
            #print key+"================\n"
            for x in l:
                b = a + "."+str(x[1])
                self.cl.hlist.add(b, text=str(x[1]))
                if not x[2]:
                    self.cl.setstatus(b, "off")
                else:
                    self.cl.setstatus(b, "on")
        self.cl.autosetmode()
        

    def selectItem(self, item):
        print item, self.cl.getstatus(item)
        if len(item.split('.')) < 2:
            for key in self.modlists:
                if item+'.dll' == key:
                    l = self.modlists[key]
                    for x in l:
                        self.cl.setstatus((item+'.'+str(x[1])),self.cl.getstatus(item))
        pass
        #print self.modlists
        #bt2 = clist(self.parent, self)
        #x = cl2.View(self.parent)
        #x.makeCheckList()

    def inputClick(self, event):
        if self.frame2:
            self.frame2.pack_forget()
            self.frame2.destroy()
        self.frame2 = Frame(self.parent, width=500,height=500)
        self.frame2.pack(fill=X, padx=5, pady=5)
        scroll = Scrollbar(self.frame2, orient=VERTICAL)
        self.selectInput = Listbox(self.frame2, yscrollcommand=scroll.set, height=25)
        for name in self.input:
            #x = mcb(top, name, pid, self)
            self.selectInput.insert(END,name)
        scroll.config (command=self.selectInput.yview)
        scroll.pack(side=RIGHT, fill=Y)
        self.selectInput.pack(side=LEFT,  fill=BOTH, expand=1)
        self.e = Entry(self.frame2)
        self.e.pack()
        b = Button(self.frame2, text="Add Input")
        b.bind("<Button-1>", self.getInput)
        b1 = Button(self.frame2, text="Done")
        b1.bind("<Button-1>", self.clearInputScreen)
        b.pack(side=BOTTOM)
        b1.pack(side=BOTTOM)

    def getInput(self, event):
        self.selectInput.insert(END,self.e.get())
        self.input.append(self.e.get())

    def clearInputScreen(self, event):
        self.frame2.pack_forget()
        self.frame2.destroy()
        
    def button3Click(self, event):
        print self.select.curselection()
        print self.procinfo[int(self.select.curselection()[0])]
        self.pid = int(self.procinfo[int(self.select.curselection()[0])][0])
        self.process = self.procinfo[int(self.select.curselection()[0])][1]
        self.frame2.pack_forget()
        self.frame2.destroy()
                                 
    def button4Click(self, event):
        l = self.cl.getselection()
        self.bp = []
        #print self.modlists
        for x in l:
            a = None
            if len(x.split('.'))<2:
                continue
            if x.split('.')[0] in self.modlists.keys():
                a = x.split('.')[0]
            elif x.split('.')[0]+'.dll' in self.modlists.keys():
                a = x.split('.')[0]+'.dll'
            #print a
            #print self.modlists[a]
            #self.modlists[a]
            if a != None:
                for ind, sel in enumerate(self.modlists[a]):
                    if sel[1] == x.split('.')[1]:
                        print sel[1]
                        self.modlists[a][ind][2] = True
                        self.bp.append((a,sel[1]))
                    #sel[2] = True
                    
        #print l
        if self.on == False:
            self.setHookPoints()
        self.frame2.pack_forget()
        self.frame2.destroy()

    def goClick(self, event):
        a = self.button5["text"]
        if self.on == True:
            self.button5["text"] = "Pause"
            self.frame2 = Frame(self.parent, width=500, height=500)
            self.frame2.pack(fill=X, padx=5, pady=5)
            self.textbox = Listbox(self.frame2,height=20,width=50)
            #self.textbox.configure(wrap=WORD)
            #textbox.configure(font=(DEFAULT_FONT_FAMILY,TEXTBOX_FONT_SIZE))
            rightScrollbar = Scrollbar(self.frame2, orient=VERTICAL, command=self.textbox.yview)
            self.textbox.configure(yscrollcommand = rightScrollbar.set)
            rightScrollbar.pack(side=RIGHT, fill=Y)
            self.textbox.pack(side=LEFT, fill=BOTH, expand=YES)
            self.textbox.bind('<ButtonRelease-1>', self.get_list)
            if len(self.input) > 0:
                b = Button(self.frame2, text="Show Input Trace")
                b.bind("<Button-1>", self.InputTrace)
                b.pack(side=BOTTOM)
            self.on = False
            self.queue.empty()
            self.update_clock()
            self.thread1 = threading.Thread(target=self.setHookPoints)
            self.thread1.start()
        else:       
            try:
                #self.dbg.detach()
                pass
            except:
                pass
            else:
                self.frame2.pack_forget()
                self.frame2.destroy()
                self.button5["text"] = "Go!"
                self.on = True
              
    def get_list(self, event):
        top = Toplevel()
        index = self.textbox.curselection()[0] #listbox1.curselection()[0]
        seltext = self.textbox.get(index)
        x = seltext.split('.')[0]
        w = Label(top, text=self.params[int(x)])
        w.pack()

    def InputTrace(self, event):
        top = Toplevel()
        lbox = Listbox(top,height=20,width=50)
            #self.textbox.configure(wrap=WORD)
            #textbox.configure(font=(DEFAULT_FONT_FAMILY,TEXTBOX_FONT_SIZE))
        rightScrollbar = Scrollbar(top, orient=VERTICAL, command=lbox.yview)
        lbox.configure(yscrollcommand = rightScrollbar.set)
        rightScrollbar.pack(side=RIGHT, fill=Y)
        lbox.pack(side=LEFT, fill=BOTH, expand=YES)
        x = ""
        for l in self.TraceData:
            lbox.insert(END,l)
        #w = Label(top, text=x)
        lbox.see("end")
        #w.pack()
        
        
        #print self.params
        #tkMessageBox.showinfo("Parameters", self.params[int(seltext)])

    def update_clock(self):
        self.textbox.after(100, self.update_clock)
        while self.queue.qsize( ):
            try:
                msg = self.queue.get(0)
                #print msg
                self.textbox.insert(END,msg)
                self.textbox.see("end")
                # Check contents of message and do whatever is needed. As a
                # simple example, let's print it (in real life, you would
                # suitably update the GUI's display in a richer fashion).
                #print msg
            except Queue.Empty:
                # just on general principles, although we don't expect this
                # branch to be taken in this case, ignore this exception!
                pass

    def exitHandler(self, dbg, args, h ):
        if args[len(args)-1] == "rand" :
            #print str(self.count)+" Exit Handler: \n"
            #print self.dbg.context.Eax
            #print self.rand
            #self.dbg.context.Eax = 0
            #self.dbg.set_register("eax",self.rand)
            #self.rand +=1000
            #print "***"
            #print self.dbg.context.Eax
            pass
    
    def myHandler(self, dbg, args ):
        buffer = ""          
        for item in args:
            data = dbg.smart_dereference(item, False)
            buffer += str(data)+"\n"
        
        #if args[len(args)-1] == "PtInRect" :
            #print buffer

        #self.data += "\n"+str(self.count)+".=== "+ args[len(args)-2] +" ==== " + args[len(args)-1]
        #self.textbox.insert(END, "\n"+str(self.count)+".=== "+ args[len(args)-2] +" ==== " + args[len(args)-1], "normal")
        self.count+=1
        self.queue.put(str(self.count)+".=== "+ args[len(args)-2] +" ==== " + args[len(args)-1])
        self.params[self.count] = buffer
        if len(self.input) > 0:
            for l in self.input:
                if l in buffer:
                    self.TraceData.append(str(self.count)+".=== "+ args[len(args)-2] +" ==== " + args[len(args)-1]+"\n")
                    self.TraceData.append(buffer)
                    self.TraceData.append("\n==========================")
                
        return DBG_CONTINUE



    def getHookContainer(self):
        hook_address2=[]
        for x in self.bp:
            try:
                hook_address1 = self.dbg.func_resolve_debuggee(x[0],x[1])
            except:
                    continue
            else:
                if hook_address1:
                    t=()
                    t=(hook_address1,x[0],x[1])
                    hook_address2.append(t)
        return hook_address2


    def setHookPoints(self):
        hooks = utils.hook_container()
        if len(self.dbg.breakpoints) > 0:
            print "\n ******+++++******\n"
            print self.dbg.breakpoints 
            for l in self.hook_address:
                hooks.remove(self.dbg, l[0])
            #self.dbg.bp_del_all()
            
        print "self.on: "+str(self.on)
        if self.on2 == True:
            self.dbg.attach(self.pid)
        self.hook_address = self.getHookContainer() 
        for l in self.hook_address:
            hooks.add( self.dbg, l[0], 2, self.myHandler, self.exitHandler, l[1], l[2] )
            #print "\n"
            print "\t", hex(l[0]), l[1], l[2]
        if self.on2 == True:
            self.on2 = False
            self.dbg.run()



class ThreadedClient(object):
    def __init__(self, master):
        self.master = master
        self.queue = Queue.Queue( )
        self.running = True
        #self.thread1 = threading.Thread(target=self.workerThread1)
        self.gui = MyApp(root, self.queue)#GuiPart(master, self.queue, self.endApplication, self.thread1)


#    def endApplication(self):
#        self.running = False
#
#    def startApplication(self):
#        self.thread1.start( )


        
root = Tix.Tk()
root.title("Epiphany")
client = ThreadedClient(root)
#myapp = MyApp(root)  ### (2)
root.mainloop()      ### (3)