# Setup New Server

mkdir /home/ssmanager

copy ssmanager to /home/ssmanager/ssmanager

mkdir /home/ssmanager/log

### setup log4rs.yaml (logging config)
copy stuff/log4rs.yaml /home/ssmanager/log4rs.yaml

### setup ssmanager.service
update stuff/ssmanager.service, maybe update url_key, check user (should be root?)
copy stuff/ssmanager.service /etc/systemd/system/ssmanager.service

### setup server_config.json
update stuff/server_config.json update server ip address
copy stuff/server_config.json /home/ssmanager/server_config.json

### Init log file to tail for initial test 
touch log/ssmanager.log

### Test
/home/ssmanager# systemctl start ssmanager.service | tail -f log/ssmanager.log

Other systemctl commands: [start, restart, status, stop]

