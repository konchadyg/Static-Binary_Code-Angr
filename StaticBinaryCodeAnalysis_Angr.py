#########################################
#CS 6332.001 - PROJECT 2				#
#Author: 	Konchady Gaurav Shenoy		#
#NETID:		KXS168430					#
#Instructor:	Dr. Zhiqiang Lin		#
#Term:		FALL 2017					#
#Submission:	October 08 2017			#
#########################################
#Static Binary Code Analysis w/ Angr	#
#########################################

import os
import sys;
import angr;
import monkeyhex
#from angrutils import *



if __name__ == '__main__':
	print "\n\n<<<<<CLE Component Analysis>>>>>"
	print ''
	filecle = raw_input("Enter filename with absolute path for CLE Analysis: ")
	if(os.path.isfile(str(filecle))):
		print "File "+str(filecle)+" exists"
	else:
		print "File "+str(filecle)+" NOT FOUND. Exiting...."
		sys.exit();
	
	###Angr Analysis of CLE begins
	
	print '------------------------------------------------------------------'
	print '******Section 1: CLE Analysis******'
	print '------------------------------------------------------------------'
	
	proj = angr.Project(filecle)
	
	mainobj= proj.loader.main_object
	pflag=0
	try:
		fgotobj = mainobj.imports['printf']
	except:
		print "printf not found. Proceeding"
		pflag=1
	
	
	print '------------------------------------------------------------------'
	print 'FileName: '+str(proj.filename)
	print '------------------------------------------------------------------'
	print '> Entry Address: '+str(hex(proj.entry))
	print '> Minimum Address: '+str(hex(proj.loader.min_addr))
	print '> Maximum Address: '+str(hex(proj.loader.max_addr))
	print '> Binary Full Name: '+str(proj.filename)
	print '> Shared Objects: '+str(proj.loader.shared_objects)
	if pflag==0:
		print '> printf GOT address: '+str(hex(fgotobj.rebased_addr))
	else:
		print '> printf GOT address: (No printf found)'
	print '---------------------------------'
	
	
	#########################################
	
	#Angr CFG Begins
	
	print "\n\n<<<<<CFG Analysis>>>>>"
	print ''
	filecle = raw_input("Enter filename with absolute path for CLE Analysis: ")
	if(os.path.isfile(str(filecle))):
		print "File "+str(filecle)+" exists"
	else:
		print "File "+str(filecle)+" NOT FOUND. Exiting...."
		sys.exit();	
	
	print '------------------------------------------------------------------'
	print '******Section 2: CFG Analysis******'
	print '------------------------------------------------------------------'	
	
	proj = angr.Project(filecle, load_options={'auto_load_libs': False})
	cfg  = proj.analyses.CFGAccurate(keep_state=True)
	
	print '------------------------------------------------------------------'
	print 'FileName: '+str(proj.filename)
	print '------------------------------------------------------------------'
	#print "This is the graph:", cfg.graph
	print "The CFG graph has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges()))
	
	entry_node = cfg.get_any_node(proj.entry)
	print "There were %d contexts for the entry block" % len(cfg.get_all_nodes(proj.entry))
	#print "Predecessors of the entry point:", entry_node.predecessors
	#print "Successors of the entry point:", entry_node.successors
	#print "Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ] 
	print "Entry Address: "+str(hex(proj.entry))
	print "Entry Function: "+str((cfg.kb.functions[proj.entry]).name)
	
	func_mang = cfg.kb.functions.function(name='main')
	print "The main function: "+str(func_mang.name)
	print "The main function starting address: "+hex(func_mang.startpoint.addr)
	
	print "Addresses of basic blocks which end in calls out to other functions inside main: "
	
	l=func_mang.get_call_sites()
	for i in range(0,len(l)):
    		x = hex(l[i])
    		print "-> "+str(x)
    	print '------------------------------------------------------------------'
    	
	#########################################
	
	#Angr Bindiff Begins
		
	print "\n\n<<<<<Bindiff Analysis>>>>>"
	print ''
	file1 = raw_input("Enter first filename with absolute path for CLE Analysis: ")
	if(os.path.isfile(str(file1))):
		print "File "+str(file1)+" exists"
	else:
		print "File "+str(file1)+" NOT FOUND. Exiting...."
		sys.exit();
	
	file2 = raw_input("Enter second filename with absolute path for CLE Analysis: ")
	if(os.path.isfile(str(file2))):
		print "File "+str(file2)+" exists"
	else:
		print "File "+str(file2)+" NOT FOUND. Exiting...."
		sys.exit();
	
	proj1 = angr.Project(file1,load_options={"auto_load_libs": False})
	proj2 = angr.Project(file2,load_options={"auto_load_libs": False})
	
	bindiff = proj1.analyses.BinDiff(proj2)
	
    	identical_functions = bindiff.identical_functions
    	differing_functions = bindiff.differing_functions
    	unmatched_functions = bindiff.unmatched_functions
    	
	print '------------------------------------------------------------------'
	print '******Section 3: Bindiff Analysis******'
	print '------------------------------------------------------------------'    	
	
	print proj1.filename+" vs "+proj2.filename
	print '\n---------------------------------'
	print 'Identical Functions:'
	print '---------------------------------'
	for a,b in identical_functions:
		print hex(a)+","+hex(b)
	print '\n---------------------------------'
	print 'Differing Functions:'
	print '---------------------------------'
	for a,b in differing_functions:
		print hex(a)+","+hex(b)	
	
	print '\n---------------------------------'
	print 'Unmatched Functions:'
	print '---------------------------------'
	#for a,b in unmatched_functions:
	#	print hex(a)+","+hex(b)	
	print str(unmatched_functions)
	print '------------------------------------------------------------------'
    	
    	#print "Identical Functions: "+str(identical_functions)
    	#print "Differing Functions: "+str(differing_functions)
    	#print "Unmatched Functions: "+str(unmatched_functions)
    	
    	#########################################
	
	print "#########################################"
	print "Program Completed"
	print "#########################################"
#########################################
#END					#
#########################################	