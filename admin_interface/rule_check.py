import subprocess
from time import time
import os
def validate_configs():
    # Check ModSecurity v3 config
    modsec_result = subprocess.run(
        ["modsecurity-check-config", "/etc/nginx/modsec/main.conf"],
        capture_output=True, text=True
    )

    # Check Nginx config
    nginx_result = subprocess.run(
        ["nginx", "-t"],
        capture_output=True, text=True
    )

    valid_modsec = modsec_result.returncode == 0
    valid_nginx = nginx_result.returncode == 0

    return {
        "modsec_ok": valid_modsec,
        "modsec_output": modsec_result.stdout + modsec_result.stderr,
        "nginx_ok": valid_nginx,
        "nginx_output": nginx_result.stdout + nginx_result.stderr,
        "all_ok": valid_modsec and valid_nginx
    }

def Reload(self): #remove checks
        #Debug only
        os.system('echo "Reload executed" >> /home/www-data/waf2py_community/applications/Waf2Py/static/logs/debug.log')
        self.out, self.err = subprocess.Popen(['sudo', '/opt/waf/nginx/sbin/nginx', '-t'], stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
        if 'syntax is ok' in str(self.err):
            self.response = 'Syntax OK'
        else:
            self.response = 'Bad Syntax: ' + str(self.err)

        if self.response == 'Syntax OK':
            #sometimes a single reload doesn't work as spected... 2 reload to solve this random issue.
            self.out, self.response = subprocess.Popen(['sudo', '/opt/waf/nginx/sbin/nginx', '-s', 'reload'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            #sometimes a single reload doesn't work as spected... 2 reload to solve this random issue.
            #second reload is performed only if there are no errors on the first reload
            if not self.response:
                time.sleep(1)
                subprocess.Popen(['sudo', '/opt/waf/nginx/sbin/nginx', '-s', 'reload'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.response = 'Reload Succesfull'

        return self.response