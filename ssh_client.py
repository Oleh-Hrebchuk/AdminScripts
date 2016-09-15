import paramiko


client=paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('remote_host',username='root',password='')

stdin, stdout, stderr = client.exec_command('ifconfig')
print stderr.readlines()
print stdout.read()
client.close()
