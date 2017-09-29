import sys
import getopt
import hashlib
import re

# Global Variables
i = 0

# Usage
def usage():
    print "Digest_Smash"
    print 
    print "Usage: digest_log_smash.py -e <log file> <pass file>"
    print " -l --log=log file_to_run - load log file"
    print " -p --pass=pass file_to_run - load pass file"
    print "Examples: "
    print "digest_log_smash.py -l testlog.log -p pass.txt"
    sys.exit(0)

# Main Program
def main():
  global i

  if not len(sys.argv[1:]):
    usage()

  # read the commandline options
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hl:p:", ["help", "log", "pass"])
  except getopt.GetoptError as err:
    print str(err)
    usage()

  for o,a in opts:
    if o in ("-h", "--help"):
      usage()
    elif o in ("-l", "--log"):
      file_name = a
    elif o in ("-p", "--pass"):
      file_pass = a
    else:
      assert False, "Unhandled Option"

  try:
    print file_name
    # Open File and Build RegEx strings
    with open(file_name) as l:
      for line in l:
        i=i + 1
        chk = 0
        sUser = re.search('username=\"([^\"]*)\"', line)
        sRealm = re.search('realm=\"([^\"]*)\"', line)
        sUri = re.search('uri=\"([^\"]*)\"', line)
        sNonce = re.search('nonce=\"([^\"]*)\"', line)
        sNc = re.search('nc=\"([^\"]*)\"', line)
        if not hasattr(sNc, 'group'):
          sNc = re.search('nc=([^,]*),', line)
        sCnonce = re.search('cnonce=\"([^\"]*)\"', line)
        sQop = re.search('qop=\"([^\"]*)\"', line)
        if not hasattr(sQop, 'group'):
          sQop = re.search('qop=([^,]*),', line)
        sResponse = re.search('response=\"([^\"]*)\"',line)

   
        HA2 = hashlib.md5("GET:" + sUri.group(1)).hexdigest()
        sStack = sNonce.group(1)+":"+sNc.group(1)+":"+sCnonce.group(1)+":"+sQop.group(1)
   

        print str(i) + ": --> " + sUser.group(1) +":"+ sRealm.group(1),
        # Open password file and test
        with open(file_pass) as f:
          for line in f:
            my_str = sUser.group(1) + ":" + sRealm.group(1) + ":" + line.rstrip()
            HA1 = hashlib.md5(my_str).hexdigest()
        
            # Check reponse hash
            response = hashlib.md5(HA1 + ":" + sStack + ":" + HA2).hexdigest()
            if sResponse.group(1) == response:
              print " [PASS] :-  %s:%s" % (sUser.group(1),line.rstrip())
              chk = 1
              break
        f.close
        if chk == 0:
          print " [FAIL] "
    l.closed
  
  except Exception as e:
    print str(e)

main()