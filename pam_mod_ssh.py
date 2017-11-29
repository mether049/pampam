import crypt, spwd, syslog
import csv
import datetime
# -*- coding: utf-8 -*-
def auth_log(host,user,passwd):
 """Send errors to default auth log"""
 today=datetime.date.today()
 time=datetime.datetime.today()
 f=open('/var/log/ssh-'+str(today)+'.csv','ab')
 csvwriter=csv.writer(f)
 syslog.openlog(facility=syslog.LOG_AUTH)
 syslog.syslog("SSH Attack Logged:(" + str(host)+":"+str(user)+":"+str(passwd)+")")
 syslog.closelog()
 attempt=[host,user,passwd,time]
 if(host!='localhost'):
  csvwriter.writerow(attempt)
 f.close()

def check_pw(user, password):
 """Check the password matches local unix password on file"""
 if((user=='root') or (user=='rootuser')):
  hashed_pw = spwd.getspnam(user)[1]
  return crypt.crypt(password, hashed_pw) == hashed_pw
 else:
  return False

def pam_sm_authenticate(pamh, flags, argv):
 try:
  user = pamh.get_user()
 except pamh.exception, e:
  return e.pam_result

 if not user:
  return pamh.PAM_USER_UNKNOWN

 try:
  resp = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, 'Password:'))
 except pamh.exception, e:
  return e.pam_result

 if not check_pw(user, resp.resp):
  auth_log(pamh.rhost, user, resp.resp)
  return pamh.PAM_AUTH_ERR

 return pamh.PAM_SUCCESS

def pam_sm_setcred(pamh, flags, argv):
 return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
 return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
 return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
 return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
 return pamh.PAM_SUCCESS
