##################################################
#  NNTP HUNTER (DISCOVER WEAK NNTP SERVERS)      #
#  27/07/2015					 #
#  - TLS enabled and code fixes			 #
#  http://www.mentalchallenge.tk		 #
##################################################
#FINAL FIX make queue part of the class as self.queue=q so we can get better performance from local
#variables
import socket
import csv
import time
import logging
import json
import threading
import ssl
from Queue import Queue
from random import randint
q=Queue()
accounts=[]
class nntp_hunter(threading.Thread):

  def __init__(self,all):
    threading.Thread.__init__(self)
    self.nntp=None
    self.ALL=all
    self.ip=None
    self.port=None
    self.ADDR=()

  def run(self):
    while not q.empty():
      item = q.get()
      self.ip=item[0]
      self.port=item[1]
      self.ADDR=(self.ip,self.port)
      if self.port in {563,564,600,663,664}: #ssl port set faster than list
        self.ssl_con()#make ssl_socket
      else:
        self.nntp=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      #self.nntp.settimeout(3)
      data=None
      try:
        self.nntp.connect(self.ADDR)
        data=self.recv_single()
#        if int(data[:3]) in [502,400,480]: # !=200 is not NNTP service
        if int(data[:3]) not in {200,201}: # 200,201 coneected ok to server
          self.nntp.close()
          logging.error('--HOST:{0}:{2} DATA:{1}'.format(self.ip,data,self.port))#NNTP CONNECT ERROR
        else:
          self.nntp.send("GROUP {}\r\n".format("alt.binaries.movies.divx"))
          data=self.recv_single()
          if int(data[:3])==480: self.nntp_auth(self.ALL)
          else: self.nntp_group()
          self.nntp.send('QUIT\r\n')
          self.nntp.close()
      except: # catch all NON NNTP responses
        self.nntp.close()
        logging.error('HOST:{0}:{2} DATA3:{1}'.format(self.ip,data,self.port))
      q.task_done()

  def recv_single(self,mark='\r\n',timeout=2.3):
    self.nntp.setblocking(0)
    total_data=[];data='';begin=time.time()    
    while 1:#if we get '\r\n' to signal end of line break loop and parse else wait for timeout 
      if time.time()-begin>timeout:
        break
      try:
        data=self.nntp.recv(8192)
        if data:
          total_data.append(data)
          if data[-2:]==mark:
            break
          begin=time.time()
        else: time.sleep(0.05)
      except: pass
    return ''.join(total_data).rstrip()

  def ssl_con(self):
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    self.nntp=ssl.wrap_socket(sock,cert_reqs=ssl.CERT_NONE,ssl_version=ssl.PROTOCOL_SSLv23)

  def nntp_auth(self,all):# all=TRUE check all else break on first find
    for x in accounts:#authinfo
      self.nntp.send("AUTHINFO USER {}\r\n".format(x[0]))
      data=self.recv_single()
      if int(data[:3])==381:
        self.nntp.send("AUTHINFO PASS {}\r\n".format(x[1]))
        data=self.recv_single()
        #data=self.recv_single()#za da ne se otkazeme pred da dobieme rezultat
        if int(data[:3])==281:
          logging.info("HOST:{2}:{3} AUTHINFO U:{0} P:{1}".format(x[0],x[1],self.ip,self.port))#logging user cred
          self.nntp_group()
          if not all:
            break # call group cmd
      if int(data[:3])==281:
        logging.info("HOST:{1}:{2} AUTHINFO U:{0}".format(x[0],self.ip,self.port)) # logging user only
        self.nntp_group()
        if not all:
          break # call group
      elif int(data[:3])==482: logging.error("HOST:{0}:{1} DATA1:{2}".format(self.ip,self.port,data))
      elif int(data[:3])==483: #MUST USE SSL
        self.nntp.close()
        self.ssl_con()#close regular and start ssl_socket
        self.nntp.connect(self.ADDR)
        self.nntp_auth(self.ALL)#continue authentication in ssl
      else: logging.error("HOST:{0}:{2} DATA2:{1}".format(self.ip,data,self.port)) # ovoj else e poveke kako kontrola dokolku response code e 38x ili ke ispecate 481 za sekoj fail attempt

  def nntp_group(self):
    self.nntp.send("GROUP {}\r\n".format("alt.binaries.movies.divx"))
    data=self.recv_single()
    #data=self.recv_single()
    if int(data[:3])==211:
      if data[3:].split().count('0'): # empty group
        logging.info("HOST:{0} EMPTY BINARY GROUP {1}".format(self.ip,data))
      else:
        logging.info("HOST:{0} BINARY GROUP EXISTS {1}".format(self.ip,data))
    else: #411
      logging.info("HOST:{0} GROUP NOT FOUND {1}".format(self.ip,data))
#shuffle funcion to randomize credentials used for authentication
def shuffle(a):
  b=len(a)-1
  while b:
    c=randint(0,b)
    a[c],a[b]=a[b],a[c]
    b-=1
#uses CSV file see example
def account_load(filename=None):
  if filename:
    with open(filename) as csvfile:
      reader = csv.DictReader(csvfile)
      for x in reader:
        accounts.append((x['USER'],x['PASS']))
#user defined login credentials
  accounts.append(('USER','PASS'))
  accounts.append(('USER1','PASS1'))

def ip_load(filename=None):
  if filename:
    with open(filename) as csvfile:
      reader = csv.DictReader(csvfile)
      for x in reader:
        q.put((x['IP'],int(x['PORT'])))
#json encoded file load
def json_open(filename=None):
    if filename:
      for x in open(filename):
        a=json.loads(x[:-2])
        q.put((a['ip'],a['ports'][0]['port']))

def main(all=0,thread_count=15):
#  account_load()
#  csv_open()  
  threads=[]
  sec=time.time()
  logging.basicConfig(filename='nntp_hunt.log',datefmt='%d.%m.%Y %H:%M:%S',format='%(asctime)s %(process)d %(thread)d %(threadName)s %(levelname)s %(message)s',level=logging.INFO,filemode='w')
  logging.info(' ======== PROGRAM START ======== ')
  for t in range(thread_count):
    t=nntp_hunter(all)
    t.daemon=True
    threads.append(t)
  for t in threads:
    t.start()
  q.join()
  logging.info(' ======== PROGRAM END ======== ')
  print("DONE IN {}".format(time.time()-sec))
  logging.shutdown()

if __name__ == '__main__':
  account_load('accounts')
  ip_load('iplist')
  main()
  
