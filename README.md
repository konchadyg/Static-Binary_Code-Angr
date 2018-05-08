# Static-Binary_Code-Angr
Using Angr for Static Binary Code Analysis
#########################################
#CS 6332.001 - PROJECT 2				#
#Author: 	Konchady Gaurav Shenoy		#
#Instructor:	Dr. Zhiqiang Lin		#
#Term:		FALL 2017					#
#Submission:	October 08 2017			#
#########################################
#Static Binary Code Analysis w/ Angr	#
#########################################
README-README-README-README-README-README

Steps to setup and Run (Ubunut Linux):
1. Place the file StaticBinaryCodeAnalysis_Angr.py in a suitable location of your choice.
2. Set the work environment for angr (Ensure other pre-steps are performed beforehand)
	$ workon angr
3. Run the python script (Python 2.7):
	(angr) $ python StaticBinaryCodeAnalysis_Angr.py
	
You will get many input prompts during the run. 
You are expected to enter the ABSOLUTE PATH of the binary. If the binary is in the current directory, then the binary name is enough.
Incorrect paths will cause the program to terminate.
4. Evaluate the on-screen output.

#########################################
Below is a sample screen output:
#########################################

(angr) konchady@konchady:~/syssec$ pwd;ls test_cle test_analysis test_diff 
/home/konchady/syssec
test_analysis  test_cle  test_diff

(angr) konchady@konchady:~/syssec$ python StaticBinaryCodeAnalysis_Angr.py 


<<<<<CLE Component Analysis>>>>>

Enter filename with absolute path for CLE Analysis: test_cle
File test_cle exists
------------------------------------------------------------------
******Section 1: CLE Analysis******
------------------------------------------------------------------
------------------------------------------------------------------
FileName: test_cle
------------------------------------------------------------------
> Entry Address: 0x8048320
> Minimum Address: 0x8048000
> Maximum Address: 0xb00c808
> Binary Full Name: test_cle
> Shared Objects: OrderedDict([('test_cle', <ELF Object test_cle, maps [0x8048000:0x804a033]>)])
> printf GOT address: 0x804a00c
---------------------------------


<<<<<CFG Analysis>>>>>

Enter filename with absolute path for CLE Analysis: test_analysis
File test_analysis exists
------------------------------------------------------------------
******Section 2: CFG Analysis******
------------------------------------------------------------------
------------------------------------------------------------------
FileName: test_analysis
------------------------------------------------------------------
The CFG graph has 61 nodes and 82 edges
There were 1 contexts for the entry block
Entry Address: 0x80483a0
Entry Function: _start
The main function: main
The main function starting address: 0x804849d
Addresses of basic blocks which end in calls out to other functions inside main: 
-> 0x80484fa
-> 0x804853d
-> 0x804849d
-> 0x804850e
-> 0x804852f
------------------------------------------------------------------


<<<<<Bindiff Analysis>>>>>

Enter first filename with absolute path for CLE Analysis: test_analysis
File test_analysis exists
Enter second filename with absolute path for CLE Analysis: test_diff
File test_diff exists
------------------------------------------------------------------
******Section 3: Bindiff Analysis******
------------------------------------------------------------------
test_analysis vs test_diff

---------------------------------
Identical Functions:
---------------------------------
0x8048314,0x8048314
0x8048470L,0x8048470L
0x8048450L,0x8048450L
0x80483a0,0x80483a0
0x8048550,0x8048560
0x80483d0,0x80483d0
0x8048380,0x8048380
0x80483e0,0x80483e0
0x8048350,0x8048350
0x8048370,0x8048370
0x8048360,0x8048360
0x8048390,0x8048390

---------------------------------
Differing Functions:
---------------------------------
0x804849d,0x804849d

---------------------------------
Unmatched Functions:
---------------------------------
(set([]), set([]))
------------------------------------------------------------------
#########################################
Program Completed
#########################################
