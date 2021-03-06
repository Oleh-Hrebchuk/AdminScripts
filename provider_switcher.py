import os
import requests
import socket
import smtplib
import base64
import json
import pickle
from email.mime.text import MIMEText
import datetime
import ast
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import paramiko
import ConfigParser


class SMS(object):
    def __init__(self, login, passwd):
        self.phone = login
        self.passwd = passwd

    def create_connect_alpha(self):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        session = requests.Session()
        data = {
            'phone': self.phone,
            'password': self.passwd
        }
        headers = {
            'Referer': 'https://alphasms.com.ua/',
        }
        session.post('https://alphasms.com.ua/ajax/login/', data=data, headers=headers, verify=False)
        return session

    def send_sms_message(self, rcpt, body):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        connect = self.create_connect_alpha()
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.7.1',
            'Content-Type': 'application/json;charset=utf-8',
            'Referer': 'https://alphasms.com.ua/panel/settings/',
        }
        list_rcpt="""""".strip()
        for number in rcpt:
            list_rcpt = list_rcpt+"""<msg recipient="{}" sender="AlphaSMS" type="0">{}</msg>\n""".format(number, body)
        texts = """
        <?xml version="1.0" encoding="utf-8" ?>
        <package login="{}" password="{}">
        <message>
        {}
        </message>
        </package>
        """.format(self.phone, self.passwd, list_rcpt)
        encode = base64.b64encode(texts)
        data = {"data": encode}
        connect.post('https://alphasms.com.ua/panelUtils/validatexml/', headers=headers, data=json.dumps(data),
                                 verify=False)
        connect.close()


class FileManagement(object):
    def add_to_file(self, path, res):
        with open('{}'.format(path), 'a') as f:
            f.write(res)

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

    def date_log(self):
        return datetime.datetime.today().strftime("%y-%m-%d %H:%M")


class GetConfig(object):
    def get_value_confing(self, section, key):
        configParser = ConfigParser.RawConfigParser()
        configFilePath = r'/opt/template-vpn/provider.conf'
        configParser.read(configFilePath)
        value = configParser.get(section, key)
        return value

    def get_dict_config(self, section, key):
        return ast.literal_eval(self.get_value_confing(section, key))

    def get_list_config(self, section, key):
        return [val.strip() for val in self.get_value_confing(section, key).split(',')]


class MailSender(FileManagement, GetConfig):
    def send_mail(self, subject_mail, message):
        user = self.get_value_confing('mail', 'user')
        pwd = self.get_value_confing('mail', 'pwd')
        FROM = self.get_value_confing('mail', 'from')
        TO = self.get_value_confing('mail', 'to')
        smtp_server = self.get_value_confing('mail', 'smtp_server')
        smtp_port = self.get_value_confing('mail', 'smtp_port')
        msg = MIMEText('{}'.format(message))
        msg['From'] = user
        msg['To'] = TO
        msg['Subject'] = subject_mail
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.ehlo()
            server.starttls()
            server.login(user, pwd)
            server.sendmail(FROM, TO, msg.as_string())
            server.quit()
        except Exception as e:
            self.add_to_file(self.path_error_log, str(self.date_log()) + ' ' + str(e) + '\n')


class CheckChannel(object):
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

    def check_channel_vpn(self, list_vpn, eth, current_name_provider, triger):
        data = {}
        for host in list_vpn:
            if self.ping(eth, host) == 0:
                data[host] = 'Up'
            else:
                data[host] = 'Down'
                self.write_file_w(current_name_provider, triger)
        return data


class SSHManager(FileManagement):
    def create_ssh_connection(self, host, user, key_filename):
        """
        Frame of ssh conection
        :param host: to connect
        :param user: user
        :return: return ssh_conect
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, 22, username=user, key_filename=key_filename)
            return ssh
        except Exception as e:
            self.add_to_file(self.path_error_log, str(self.date_log()) + ' ' + str(e) + ' ' + host + '\n')
            self.send_mail('Trigger: Script execution error', 'Current provider: {}\n'.
                           format(str(e)))

    def ssh_replace_data(self, host, path_file, old_word, replace_word, key_filename, login):
        """
        This method replace data via ssh in file
        :param host: host
        :param path_file: path to file
        :param old_word: word to replace
        :param replace_word: new word
        :return: return None
        """
        try:
            ssh_connect = self.create_ssh_connection(host, login, key_filename)
            sftp = ssh_connect.open_sftp()
            with sftp.open('{}'.format(path_file), 'r')as file_edit:
                text = file_edit.read()
            with sftp.open('{}'.format(path_file), 'w')as file_edit:
                file_edit.write(text.replace(old_word, replace_word))
            sftp.close()
        except Exception as e:
            self.add_to_file(self.path_error_log, str(self.date_log()) + ' ' + str(e) + ' ' + host + '\n')
            self.send_mail('Trigger: Script execution error', 'Current provider: {}\n'.
                           format(str(e)))
        finally:
            if ssh_connect:
                ssh_connect.close()

    def ssh_copy_file(self, host, src_dir, dst_dir, key_filename, login):
        """
        This method replace copy file to remote host
        :param host: host
        :param src_dir: source file
        :param dst_dir: destination file
        :return: None
        """
        try:
            ssh_connect = self.create_ssh_connection(host, login, key_filename)
            sftp = ssh_connect.open_sftp()
            # backup tcrules
            with sftp.open(dst_dir, 'r')as f:
                data = f.read()
            if 'tc-rulses-core' in data:
                sftp.get(dst_dir, '/opt/template-vpn/tcrules')
            sftp.put(src_dir, dst_dir)
            sftp.close()
        except Exception as e:
            self.add_to_file(self.path_error_log, str(self.date_log()) + ' ' + str(e) + ' ' + host + '\n')
            self.send_mail('Trigger: Script execution error', 'Current provider: {}\n'.
                           format(str(e)))
        finally:
            if ssh_connect:
                ssh_connect.close()

    def ssh_restart_service(self, host, name_service, check, key_filename, login):
        """
            This could restart shorewall via ssh with check (check:'yes') and other services without check service.
            :param host: host
            :param name_service: service of linux(ipsec or shorewall)
            :param check: use 'yes' for check shorewall
            :return: None
        """
        try:
            ssh_connect = self.create_ssh_connection(host, login, key_filename)
            if check == 'yes':
                stdin, stdout, stderr = ssh_connect.exec_command('/etc/init.d/{} check'.format(name_service))
                if 'Shorewall configuration verified' in stdout.read():
                    ssh_connect.exec_command('/etc/init.d/{} restart'.format(name_service))
            else:
                ssh_connect.exec_command('/etc/init.d/{} restart'.format(name_service))
        except Exception as e:
            self.add_to_file(self.path_error_log, str(self.date_log()) + ' ' + str(e) + ' ' + host + '\n')
            self.send_mail('Trigger: Script execution error', 'Current provider: {}\n'.
                           format(str(e)))
        finally:
            if ssh_connect:
                ssh_connect.close()

    def ssh_replace_left(self, host, path_file, replace_word, word_index, key_filename, login):
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
            ssh_connect = self.create_ssh_connection(host, login, key_filename)
            sftp = ssh_connect.open_sftp()
            with sftp.open('{}'.format(path_file), 'r')as file_edit:
                text = file_edit.read()
            for line in text.split('\n'):
                if 'left =' in line:
                    old_word = line[line.index(word_index) + len(word_index):]
                    break
            if old_word != '':
                with sftp.open('{}'.format(path_file), 'w')as file_edit2:
                    file_edit2.write(text.replace(old_word + '\n', replace_word + '\n'))
            else:
                self.add_to_file(self.path_error_log, str(self.date_log()) +
                                 ' ' + 'Not found provider for replace' + ' ' + host + '\n')
                self.send_mail('Trigger: Script execution error', 'Not found provider for replace')
            sftp.close()
        except Exception as e:
            self.add_to_file(self.path_error_log, str(self.date_log()) + ' ' + str(e) + ' ' + host + '\n')
            self.send_mail('Trigger: Script execution error', 'Current provider: {}\n'.
                           format(str(e)))
        finally:
            if ssh_connect:
                ssh_connect.close()

    def ssh_replace_right(self, path_file, key_filename, login):
        """
        This method change configuratin via ssh 'right'. This get from current.log and set to right
         And this restart ipsec vpn.
        :param path_file: ipsec file
        :return: None
        """
        old_word = ''
        new_state = self.read_file('/opt/template-vpn/log/current-state.txt')
        for reg in self.regions:
            for host in self.regions[reg]:
                if self.check_open_sockets(host, 22) is True:
                    try:
                        ssh = self.create_ssh_connection(host, login, key_filename)
                        sftp = ssh.open_sftp()
                        with sftp.open('{}'.format(path_file), 'r')as file_edit:
                            text = file_edit.read()
                            for prov in self.list_providers:
                                for line in text.split('\n'):
                                    if prov in line and 'right' in line and '#' not in line:
                                        old_word = prov
                                        break
                                    else:
                                        pass
                        if old_word != '':
                            with sftp.open('{}'.format(path_file), 'w')as file_edit2:
                                file_edit2.write(text.replace(old_word + '\n', new_state + '\n'))
                                ssh.exec_command('/etc/init.d/ipsec restart')
                        else:
                            self.send_mail('Trigger: Script execution error', 'Not found provider for replace')
                        sftp.close()
                    except Exception, e:
                        self.add_to_file(self.path_error_log, str(self.date_log()) + ' ' + str(e) + ' ' + host + '\n')
                        self.send_mail('Trigger: Script execution error', 'Current provider: {}\n'.
                                       format(str(e)))
                    finally:
                        if ssh:
                            ssh.close()
            else:
                continue


class ChangeProvider(SSHManager, CheckChannel, MailSender, GetConfig, SMS):
    def __init__(self):
        """
        :param ping_vpn: This variable is ip which we check if vpn is alive.
        :param ping_google_ns: google dns for check if provider is alive
        :param eth_primary: eth0 which change on alpha
        :param eth_reserve: eth0:0 reserve gateway
        :param ip_gate_primary: ip primary provider
        :param ip_gate_reserve: ip reserver provider
        :param eth_prim_local: ip alias primary local beta
        :param eth_reserve_loc: ip alias reserver local beta
        :param regions: list regions providers
        :param alpha: ip local gate
        :return: None
        """
        self.ping_google_ns = self.get_value_confing('local-providers', 'ping_google_ns')
        self.eth_primary = self.get_value_confing('local-providers', 'eth_primary')
        self.eth_reserve = self.get_value_confing('local-providers', 'eth_reserve')
        self.ip_gate_primary = self.get_value_confing('local-providers', 'ip_gate_primary')
        self.ip_gate_reserve = self.get_value_confing('local-providers', 'ip_gate_reserve')
        self.ip_prim_loc_alias = self.get_value_confing('local-providers', 'ip_prim_loc_alias')
        self.ip_reserve_loc_alias = self.get_value_confing('local-providers', 'ip_reserve_loc_alias')
        self.regions = self.get_dict_config('region-providers', 'dict_reg')
        self.vpn_list = self.get_list_config('region-providers', 'vpn_list')
        self.alpha = self.get_value_confing('local-providers', 'alpha')
        self.list_providers = self.get_list_config('local-providers', 'list_providers')
        self.login = self.get_value_confing('ssh', 'login')
        self.path_log_primary = self.get_value_confing('work-file', 'path_log_primary')
        self.path_current_name_provider = self.get_value_confing('work-file', 'current_name_provider')
        self.path_error_log = self.get_value_confing('work-file', 'error_log')
        self.path_shorewall_hosts = self.get_value_confing('work-file', 'shorewall_hosts')
        self.path_ipsec_conf = self.get_value_confing('work-file', 'ipsec_conf')
        self.path_key_filename = self.get_value_confing('work-file', 'key_filename')
        self.path_tcrules_wnet_t = self.get_value_confing('work-file', 'tcrules_wnet_t')
        self.path_tcrules_uarnet_t = self.get_value_confing('work-file', 'tcrules_uarnet_t')
        self.path_tcrules_t = self.get_value_confing('work-file', 'tcrules_t')
        self.path_tcrules = self.get_value_confing('work-file', 'tcrules')
        super(SMS,self).__init__()
        self.phone = self.get_value_confing('alpha-sms', 'phone')
        self.passwd = self.get_value_confing('alpha-sms', 'passwd')

    def switch_to_reserve(self):
        """
        This method switch from primary provider to reserve provider and restart shorewall and ipsec on remote regions.
        :return:
        """
        self.send_sms_message(['+380975448562'], 'kyki')
        if self.ping(self.ip_prim_loc_alias, '8.8.8.3') == 0:
            self.write_log_status(self.path_log_primary, '0')
        else:
            self.write_log_status(self.path_log_primary, '1')
            if self.ping(self.ip_reserve_loc_alias, self.ping_google_ns) == 0:
                self.ssh_replace_data(self.alpha, self.path_shorewall_hosts, self.eth_primary,
                                      self.eth_reserve, self.path_key_filename, self.login)
                self.ssh_replace_left(self.alpha, self.path_ipsec_conf, self.ip_gate_reserve, 'left = ',
                                      self.path_key_filename, self.login)
                self.write_file_w(self.path_current_name_provider, str(self.ip_gate_reserve))
                self.ssh_copy_file(self.alpha, self.path_tcrules_wnet_t, self.path_tcrules, self.path_key_filename,
                                   self.login)
                # self.ssh_restart_service(self.alpha, 'shorewall', 'yes')
                # self.ssh_restart_service(self.alpha,'ipsec', 'no')
                self.ssh_replace_right(self.path_ipsec_conf, self.path_key_filename, self.login)
                self.send_mail('Trigger: Moved to Reserve provider', 'Current provider: {}\n'.
                               format(self.read_file(self.path_current_name_provider)))

                self.send_mail('Trigger: Status VPN', 'Status VPN: Up\Down: {}\n'.format(self.check_channel_vpn(
                    self.vpn_list, self.ip_reserve_loc_alias, self.path_current_name_provider, triger='triger')))

    def switch_to_primary(self):
        """
        This method revert to primary provider after repaired channel internet.
        :return: None
        """
        #self.send_sms_message(['+380975448562'], 'kyki')
        if self.ping(self.ip_prim_loc_alias, self.ping_google_ns) == 0 and self.ping(self.ip_reserve_loc_alias,
                                                                                     self.ping_google_ns) == 1:
            self.ssh_replace_data(self.alpha, self.path_shorewall_hosts, self.eth_reserve, self.eth_primary,
                                  self.path_key_filename, self.login)
            self.ssh_replace_left(self.alpha, self.path_ipsec_conf, self.ip_gate_primary, 'left = ',
                                  self.path_key_filename, self.login)
            self.write_file_w(self.path_current_name_provider, str(self.ip_gate_primary))
            self.ssh_copy_file(self.alpha, self.path_tcrules_uarnet_t, self.path_tcrules, self.path_key_filename,
                               self.login)
            # self.ssh_restart_service(self.alpha, 'shorewall', 'yes')
            # self.ssh_restart_service(self.alpha, 'ipsec', 'no')
            self.ssh_replace_right(self.path_ipsec_conf, self.path_key_filename, self.login)
            self.send_mail('Trigger: Moved to Primary provider immediately', 'Current provider: {}\n'.
                           format(self.read_file(self.path_current_name_provider)))
            self.send_mail('Trigger: Status VPN', 'Status VPN: Up\Down: {}\n'.format(self.check_channel_vpn(
                self.vpn_list, self.ip_reserve_loc_alias, self.path_current_name_provider, triger='triger')))
        else:
            if '1' not in self.read_file(self.path_log_primary):
                self.ssh_replace_data(self.alpha, self.path_shorewall_hosts, self.eth_reserve, self.eth_primary,
                                      self.path_key_filename, self.login)
                self.ssh_replace_left(self.alpha, self.path_ipsec_conf, self.ip_gate_primary, 'left = ',
                                      self.path_key_filename, self.login)
                self.write_file_w(self.path_current_name_provider, str(self.ip_gate_primary))
                self.ssh_copy_file(self.alpha, self.path_tcrules_t, self.path_tcrules, self.path_key_filename,
                                   self.login)
                # self.ssh_restart_service(self.alpha, 'shorewall', 'yes')
                # self.ssh_restart_service(self.alpha, 'ipsec', 'no')
                self.ssh_replace_right(self.path_ipsec_conf, self.path_key_filename, self.login)
                self.send_mail('Trigger: Moved to Primary provider', 'Current provider: {}\n'.
                               format(self.read_file(self.path_current_name_provider)))
                self.send_mail('Trigger: Status VPN', 'Status VPN: Up\Down: {}\n'.format(self.check_channel_vpn(
                    self.vpn_list, self.ip_reserve_loc_alias, self.path_current_name_provider, triger='triger')))
            else:
                if self.ping(self.ip_prim_loc_alias, self.ping_google_ns) == 0:
                    self.write_log_status(self.path_log_primary, '0')
                else:
                    self.write_log_status(self.path_log_primary, '1')

b = ChangeProvider()

if 'prov1' in b.read_file(b.path_current_name_provider):
    b.switch_to_reserve()
    print 'sw to reserve'
elif 'prov2' in b.read_file(b.path_current_name_provider):
    print 'sw to primary'
    b.switch_to_primary()
else:
    pass

'''
config = paramiko.SSHConfig()
config.parse(open(os.path.expanduser('~/.ssh/config')))
host = config.lookup('host')
print host
ssh = paramiko.SSHClient()
ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(host['hostname'], username=host['user'], key_filename='/root/.ssh/id_rsa')
stdin, stdout, stderr = ssh.exec_command('ifconfig')`
print stdout.read()
ssh.close()
'''

