#!/usr/bin/env python

import binascii
import re
import datetime
import os
import string

fullfilelist = []
filelist = []
eventslist = []
tuplelist = []
EVENTLOGTYPE = ['EVENTLOG_AUDIT_FAILURE','EVENTLOG_AUDIT_SUCCESS','EVENTLOG_ERROR_TYPE','EVENTLOG_INFORMATION_TYPE','EVENTLOG_WARNING_TYPE']

def removeNonAscii(k):
    list1 = []
    for char in k:
        if ord(char) < 32 or ord(char) > 127:
            list1.append('#')
        else:
            list1.append(char)
    result = ''.join(list1)
    return result

def l_endian_2_ascii(data):
    bigendlist = []
    for i in range(0, len(data),2):
        bigendlist.insert(0, data[i:i+2])
    joined = ''.join(bigendlist)
    return int(joined, 16)


print 'working...'

validdir = False
while validdir == False:
    workingdir = raw_input('Input Target Directory: ')
    if os.path.isdir(workingdir):
        validdir = True
    else:
        print 'Invalid or missing directory!'

filelist = os.listdir(workingdir)
for filename in filelist:
    if filename != 'evtparse.csv' and filename != 'debug.txt' and os.path.isfile(os.path.join(workingdir,filename)) == True:
        fullfilelist.append(os.path.join(workingdir,filename))
        
outputfile = os.path.join(workingdir,'evtparse.csv')

print outputfile
f = open(outputfile, 'w')
preamble = 'SOURCE FILENAME,RECORD NUMBER,TIME GEN,TIME WRITE,CATEGORY,EVENTID,SOURCE,COMPUTER,SID,STRINGS,RAW DATA (HEX),DECODED DATA\n'
f.write(preamble)
for filename in fullfilelist:

    linestring = open(filename, 'rb').read()
    print 'Analyzing: ' + filename
    hexed = binascii.hexlify(linestring)
    matchline = '(.{,8})(4c664c65)'
    match = re.finditer(matchline,hexed)

    for item in match:
        length = l_endian_2_ascii(item.group(1))*2
        startpoint =  item.start()
        itemtuple = (startpoint, length)
        tuplelist.append(itemtuple)
    for item in tuplelist:
        if item[1] != 96:
            eventslist.append(hexed[item[0]:(item[0]+item[1])])

    tempval = ''


    for item in eventslist:
        #XX: How can ClosingRecordNumber (11th item) be 16 bits 
        #    when RecordNumber (3rd item) is 32 bits?
        matchline = '(.{,8})(4c664c65)(.{,8})(.{,8})(.{,8})(.{,4})(.{,4})(.{,4})(.{,4})(.{,4})(.{,4})(.{,8})(.{,8})(.{,8})(.{,8})(.{,8})(.{,8})(.*)'
        match = re.search(matchline,item)


        if match and len(match.group(18)) > 1 and len(match.group(1)) > 0:
            parselength = l_endian_2_ascii(match.group(1))*2
            parsesidlength = l_endian_2_ascii(match.group(14))*2
            parsesidoffset = l_endian_2_ascii(match.group(15))*2
            parsestringnum = l_endian_2_ascii(match.group(8))
            parsestringoffset = l_endian_2_ascii(match.group(13))*2
            parsedatalength = l_endian_2_ascii(match.group(16))*2
            parsedataoffset = l_endian_2_ascii(match.group(17))*2
            variable = match.group(18)


            start_sid = 0
            start_sid = parsesidoffset - 112
            strings_length = 0
            strings_length = parsedataoffset - parsestringoffset


            matchline2 = '(.{,' + str(start_sid) + '})' + '(.{,' + str(parsesidlength) + '})' + '(.{,' + str(strings_length) + '})' + '(.{,' + str(parsedatalength) + '})'
            try:
                match2 = re.search(matchline2,variable)
            except:
                pass
                start_sid = 'ERROR'

            if match2:
                source_and_computer = removeNonAscii(binascii.unhexlify(match2.group(1)))
                source_and_computer_orig = source_and_computer
                
                if match2.group(4) != '' and match2.group(2) != '':
                    sidtemp = match2.group(2)
                    sidmatchline = '(.{,2})(.{,2})(.{,12})(.{,8})(.{,8})(.{,8})(.{,8})(.{,8})'
                    sidmatch = re.search(sidmatchline,sidtemp)
                    if sidmatch:
                        sid1 = int(sidmatch.group(1))
                        sid2 = int(sidmatch.group(2))
                        sid3 = int(sidmatch.group(3))
                        sid4 = l_endian_2_ascii(sidmatch.group(4))
                        if sid2 == 5:
                            sid5 = l_endian_2_ascii(sidmatch.group(5))
                            sid6 = l_endian_2_ascii(sidmatch.group(6))
                            sid7 = l_endian_2_ascii(sidmatch.group(7))
                            sid8 = l_endian_2_ascii(sidmatch.group(8))
                            finalsid = str('S-' + str(sid1) + '-' + str(sid3) + '-' + str(sid4) + '-' + str(sid5) + '-' + str(sid6) + '-' + str(sid7) + '-' + str(sid8)) 
                        else:
                            finalsid = str('S-' + str(sid1)+ '-' + str(sid3) + '-' + str(sid4))
         
                else:
                    finalsid = 'NOSID'

                strings = removeNonAscii(binascii.unhexlify(match2.group(3)))
                data = removeNonAscii(binascii.unhexlify(match2.group(4)))
                data = re.sub(',',';',data)
                hexdata = match2.group(4)
                if not hexdata:
                    hexdata = 'NODATA'
                strings = re.sub('###',' ',strings).replace('#','')
                strings = re.sub(',',';',strings)
                if not strings:
                    strings = 'NOSTRINGS'
                if not data:
                    data = 'NODATA'
                if len(data) > 0:                 
                    goodcount = 0
                    for char in data:
                        if char != '#':
                            goodcount = goodcount + 1
                    readable_percent = int(((float(goodcount)) / float(len(data)))*100)
                    if readable_percent > 60:
                        pass
                    else:
                        data = 'NONASCIIDATA'
                else:
                    data = 'NONASCIIDATA'
                source_and_computer = re.sub('###',',',source_and_computer)
                source_and_computer = source_and_computer.replace('#','')
                if source_and_computer[-1] == ',':
                    source_and_computer = source_and_computer.rstrip(',')
     
        if match and len(match.group(18)) > 1:
            typetemp = l_endian_2_ascii(match.group(8))
            if typetemp == 10:
                tempval = EVENTLOGTYPE[0]
            if typetemp == 8:
                tempval = EVENTLOGTYPE[1]
            if typetemp == 1:
                tempval = EVENTLOGTYPE[2]
            if typetemp == 2:
                tempval =  EVENTLOGTYPE[3]
            if typetemp == 4:
                tempval = EVENTLOGTYPE[4]
            recordnum = l_endian_2_ascii(match.group(3))
            eventID = l_endian_2_ascii(match.group(6))
            timegen =  datetime.datetime.utcfromtimestamp(l_endian_2_ascii(match.group(4)))
            timewrite =  datetime.datetime.utcfromtimestamp(l_endian_2_ascii(match.group(5)))
            lineoutput = str("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (filename,recordnum,timegen,timewrite,tempval,eventID,source_and_computer,finalsid,strings,hexdata,data))
            f.write(lineoutput)
print 'Complete'
f.close()
