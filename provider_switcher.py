import os
import paramiko
import socket
import smtplib
from email.mime.text import MIMEText


class FileManagement(object):
    def add_to_file(self, path, res):
        f = open('{}'.format(path), 'a')
        f.write(res)
        f.close()

    def write_file_w(self, path, res):
        with open('{}'.format(path), 'w')as f:
            f.write(res)

    def read_file(self, path):
        with open('{}'.format(path), 'r')as f:
            read_file = f.read()
        return read_file

    def write_log_status(self, path, res):
        """
        write log primary provider were status ping new add to end
        first item delete
        """
        with open('{}'.format(path), 'r')as fr:
            list_file = fr.readline()
        if len(list_file) > 5:
            new_list = list_file[1:]
            self.write_file_w('{}'.format(path), new_list + res)
        else:
            self.add_to_file('{}'.format(path), res)


class MailSender(object):
    def send_mail(self, subject_mail, message):
        user = 'oleh.hrebchuk@gmail.com'
        pwd = ''
        FROM = user
        TO = 'oleh.hrebchuk@test.com'
        msg = MIMEText('{}'.format(message))
        msg['From'] = user
        msg['To'] = TO
        msg['Subject'] = subject_mail
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.ehlo()
            server.starttls()
            server.login(user, pwd)
            server.sendmail(FROM, TO, msg.as_string())
            server.quit()
            print 'send succs'
        except Exception as e:
            print e

class CheckChannelServer(FileManagement):
    # Static vars
    path_log_primary = '/opt/template-vpn/log/log.txt'
    current_name_provider = '/opt/template-vpn/log/current-state.txt'
    path_time = '/opt/template-vpn/log/time.log'
    path_ipsec = '/opt/template-vpn/ternopil/uarnet/ipsec.conf'
    # providers which replace right
    list_providers = ['prim_provider', 'reserve_prov']
    error_log = '/opt/template-vpn/log/error.log'
    login = 'root'
    password = 'toor'

    def __init__(self, ping_vpn, ping_google_ns, eth_primary, eth_reserve, ip_gate_primary, ip_gate_reserve,
                 eth_prim_local, eth_reserve_loc, regions, alpha):

        self.ping_vpn = ping_vpn
        self.ping_google_ns = ping_google_ns
        self.eth_primary = eth_primary
        self.eth_reserve = eth_reserve
        self.ip_gate_primary = ip_gate_primary
        self.ip_gate_reserve = ip_gate_reserve
        self.eth_prim_local = eth_prim_local
        self.eth_reserve_loc = eth_reserve_loc
        self.regions = regions
        self.alpha = alpha

    def check_open_sockets(self, host, port):
        """
        This method check if server port is listen
        :param host: host of check
        :param port: check port
        :return: Boolean
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        res = s.connect_ex((host, port))
        s.close()
        if res:
            return False
        else:
            return True

    def create_ssh_conection(self, host, user, password):
        """
        Frame of ssh conection
        :param host: to connect
        :param user: user
        :param password: pass
        :return: return ssh_conect
        """
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, 22, username=user, password=password)
        return ssh

    def ssh_replace_data(self, host, path_file, old_word, replace_word):
        """
        This method replace data via ssh in file
        :param host: host
        :param path_file: path to file
        :param old_word: word to replace
        :param replace_word: new word
        :return: return None
        """
        try:
            ssh_connect = self.create_ssh_conection(host, self.login, self.password)
            sftp = ssh_connect.open_sftp()
            with sftp.open('{}'.format(path_file), 'r')as file_edit:
                text = file_edit.read()
            with sftp.open('{}'.format(path_file), 'w')as file_edit:
                file_edit.write(text.replace(old_word, replace_word))
            sftp.close()
        except Exception as e:
            self.add_to_file(self.error_log, e)
        finally:
            if ssh_connect:
                ssh_connect.close()

    def ssh_copy_file(self, host, src_dir, dst_dir):
        """
        This method replace copy file to remote host
        :param host: host
        :param src_dir: source file
        :param dst_dir: destination file
        :return: None
        """
        try:
            ssh_connect = self.create_ssh_conection(host, self.login, self.password)
            sftp = ssh_connect.open_sftp()
            sftp.put(src_dir, dst_dir)
            sftp.close()
        except Exception as e:
            self.add_to_file(self.error_log, e)
        finally:
            if ssh_connect:
                ssh_connect.close()

    def ssh_restart_service(self, host, name_service, check):
        """
        This could restart shorewall via ssh with check (check:'yes') and other services without check service.
        :param host: host
        :param name_service: service of linux(ipsec or shorewall) 
        :param check: use 'yes' for check shorewall
        :return: None
        """
        try:
            ssh_connect = self.create_ssh_conection(host, self.login, self.password)
            if check == 'yes':
                stdin, stdout, stderr = ssh_connect.exec_command('/etc/init.d/{} check'.format(name_service))
                if 'Shorewall configuration verified' in stdout.read():
                    stdin, stdout, stderr = ssh_connect.exec_command('/etc/init.d/{} restart'.format(name_service))
            else:
                stdin, stdout, stderr = ssh_connect.exec_command('/etc/init.d/{} restart'.format(name_service))
        except Exception as e:
            self.add_to_file(self.error_log, e)
        finally:
            if ssh_connect:
                ssh_connect.close()

    def ssh_get_replace_left(self, host, path_file, replace_word, word_index):
        """
        This method replace in ipsec file. Find in file left ip which need replace.
        And replace left ip to new ip changed provider
        :param host: host
        :param path_file: ipsec.conf 
        :param replace_word: new reserver gate which should changed in ipsec file
        :param word_index: 'left = '
        :return: None
        """
        old_word = ''
        try:
            ssh_connect = self.create_ssh_conection(host, self.login, self.password)
            sftp = ssh_connect.open_sftp()
            with sftp.open('{}'.format(path_file), 'r')as file_edit:
                text = file_edit.read()
            for line in text.split('\n'):
                if 'left =' in line:
                    old_word = line[line.index(word_index) + len(word_index):]
                    break
            with sftp.open('{}'.format(path_file), 'w')as file_edit:
                file_edit.write(text.replace(old_word, replace_word))
            sftp.close()
        except Exception as e:
            self.add_to_file(self.error_log, e)
        finally:
            if ssh_connect:
                ssh_connect.close()

    def ssh_restart_ipsec(self, path_file):
        """
        This method change configuratin via ssh 'right'. This get from current.log and set to right
         And this restart ipsec vpn.
        :param path_file: ipsec file
        :return: None
        """
        
        old_word = ''
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for reg in self.regions:
            for host in self.regions[reg]:
                print host
                if self.check_open_sockets(host, 22) is True:
                    try:
                        ssh.connect(host, 22, username='root', password='toor')
                        sftp = ssh.open_sftp()
                        with sftp.open('{}'.format(path_file), 'r')as file_edit:
                            text = file_edit.read()
                            for prov in self.list_providers:

                                for line in text.split('\n'):
                                    if prov in line and 'right' in line and '#' not in line:
                                        print prov
                                        old_word = prov
                                        break
                                    else:
                                        pass
                        with sftp.open('{}'.format(path_file), 'w')as file_edit:
                            file_edit.write(
                                text.replace(old_word, self.read_file('/opt/template-vpn/log/current-state.txt')))
                            sftp.close()
                    except Exception, e:
                        print e
                    ssh.close()
                else:
                    continue

    def ping(self, eth, host):
        """
        Chack if host is alive
        :param eth: ping from alias
        :param host: ping host
        :return: 1 or 0
        """
        response = os.system('ping -c 1 -W 1 -I {} {} > /dev/null'.format(eth, host))
        if response == 0:
            return 0
        else:
            return 1

    def switch_to_reserve(self):
        """
        This method switch from primary provider to reserve provider and restart shorewall and ipsec on remote regions. 
        :return: 
        """
        if self.ping(self.eth_prim_local, '8.8.8.8') == 0:
            self.write_log_status(self.path_log_primary, '0')
        else:
            self.write_log_status(self.path_log_primary, '1')
            if self.ping(self.eth_reserve_loc, self.ping_google_ns) == 0:
                self.ssh_replace_data(self.alpha, '/etc/shorewall/hosts', self.eth_primary, self.eth_reserve)
                self.ssh_get_replace_left(self.alpha, '/etc/ipsec.conf', self.ip_gate_reserve, 'left = ')
                self.write_file_w(self.current_name_provider, str(self.ip_gate_reserve))
                self.ssh_copy_file(self.alpha, '/opt/template-vpn/tcrules_wnet', '/etc/shorewall/tcrules')
                self.ssh_restart_service(self.alpha, 'cron', 'no')
                self.ssh_restart_ipsec('/etc/ipsec.conf')
                if self.ping(self.eth_prim_local, self.ping_vpn) == 0:
                    pass
                else:
                    # self.write_file_w(self.current_name_provider, 'triger')
                    pass
            else:
                pass

    def switch_to_primary(self):
        """
        This method revert to primary provider after repaired channel internet.
        :return: None
        """
        if self.ping(self.eth_prim_local, self.ping_google_ns) == 0 and self.ping(self.eth_reserve_loc,
                                                                                  self.ping_google_ns) == 1:
            self.ssh_replace_data(self.alpha, '/etc/shorewall/hosts', self.eth_reserve, self.eth_primary)
            self.ssh_get_replace_left(self.alpha, '/etc/ipsec.conf', self.ip_gate_primary, 'left = ')
            self.write_file_w(self.current_name_provider, str(self.ip_gate_primary))
            self.ssh_copy_file(self.alpha, '/opt/template-vpn/tcrules_uarnet', '/etc/shorewall/tcrules')
            self.ssh_restart_service(self.alpha, 'cron', 'no')
        else:
            if '1' not in self.read_file(self.path_log_primary):
                self.ssh_replace_data(self.alpha, '/etc/shorewall/hosts', self.eth_reserve, self.eth_primary)
                self.ssh_get_replace_left(self.alpha, '/etc/ipsec.conf', self.ip_gate_primary, 'left = ')
                self.write_file_w(self.current_name_provider, str(self.ip_gate_primary))
                self.ssh_copy_file(self.alpha, '/opt/template-vpn/tcrules', '/etc/shorewall/tcrules')
                self.ssh_restart_service(self.alpha, 'cron', 'no')
            else:
                if self.ping(self.eth_prim_local, self.ping_google_ns) == 0:
                    self.write_log_status(self.path_log_primary, '0')
                else:
                    self.write_log_status(self.path_log_primary, '1')
                    print self.ping(self.eth_prim_local, self.ping_google_ns)

    def triger(self):
        pass



if 'ip_prim' in b.read_file(b.current_name_provider):
    b.switch_to_reserve()
elif 'ip_reserve' in b.read_file(b.current_name_provider):
    b.switch_to_primary()


