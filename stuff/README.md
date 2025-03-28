# Setup New Server

<code>mkdir /home/ssmanager</code>

### Build SSManager
(I use Cargo "cross", but it can also be built in Docker using the docker/linux-cross/Dockerfile image)

<code>
cross build --target x86_64-unknown-linux-gnu --bin ssmanager  --features "manager, database" --release
</code>

copy ssmanager to /home/ssmanager/ssmanager
<code>mkdir /home/ssmanager/log</code>

### setup log4rs.yaml (logging config)
copy stuff/log4rs.yaml /home/ssmanager/log4rs.yaml

### setup ssmanager.service
update stuff/ssmanager.service, maybe update url_key, check user (should be root?)
copy stuff/ssmanager.service /etc/systemd/system/ssmanager.service

### setup server_config.json
update stuff/server_config.json update server ip address
copy stuff/server_config.json /home/ssmanager/server_config.json

### Init log file to tail for initial test 
<code>touch log/ssmanager.log</code>

### Test
/home/ssmanager# <code>systemctl start ssmanager.service | tail -f log/ssmanager.log </code>

Other systemctl commands: [start, restart, status, stop]

