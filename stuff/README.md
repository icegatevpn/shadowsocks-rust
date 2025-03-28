Setup New Server:

mkdir /home/ssmanager

copy ssmanager to /home/ssmanager/ssmanager

mkdir /home/ssmanager/log

copy stuff/log4rs.yaml /home/ssmanager/log4rs.yaml

update stuff/ssmanager.service, maybe update url_key, check user (should be root?)
copy stuff/ssmanager.service /etc/systemd/system/ssmanager.service

update stuff/server_config.json update server ip address
copy stuff/server_config.json /home/ssmanager/server_config.json

TEST:
/home/ssmanager# systemctl start ssmanager.service | tail -f log/ssmanager.log

Other systemctl commands: [start, restart, status, stop]

