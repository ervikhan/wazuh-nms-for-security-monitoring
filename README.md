<h2>Setup Wazuh for Security Monitoring</h2>
- **Base On Ubuntu 20.04**
- **Wazuh Version : v4.3.10**

<h3>Wazuh Indexer Installation</h3>
- **Generate Certificate**
    - Create directory
        
        ```bash
        mkdir /home/ervikhan/wazuh/certs
        ```
        
        ```bash
        cd /home/ervikhan/wazuh/certs
        ```
        
    - Download `wazuh-certs-tool.sh` and `config.yml`
        
        ```bash
        curl -sO https://packages.wazuh.com/4.3/wazuh-certs-tool.sh
        ```
        
        ```bash
        curl -sO https://packages.wazuh.com/4.3/config.yml
        ```
        
    - Edit file
        
        ```bash
        nano config.yml
        ```
        
        ```bash
        nodes:
          # Wazuh indexer nodes
          indexer:
            - name: node-1 #INDEXER NODE
              ip: 192.168.2.4 #<indexer-node-ip>
            #- name: node-2
            #  ip: <indexer-node-ip>
            #- name: node-3
            #  ip: <indexer-node-ip>
        
          # Wazuh server nodes
          # If there is more than one Wazuh server
          # node, each one must have a node_type
          server:
            - name: wazuh-1 #YOUR SERVER NODE NAME
              ip: 192.168.2.4 #<wazuh-manager-ip>
            #  node_type: master
            #- name: wazuh-2
            #  ip: <wazuh-manager-ip>
            #  node_type: worker
            #- name: wazuh-3
            #  ip: <wazuh-manager-ip>
            #  node_type: worker
        
          # Wazuh dashboard nodes
          dashboard:
            *- name: dashboard #DASHBOARD NODE NAME
              ip: 192.168.2.4 #DASHBOARD NODE IP
        ```
        
    - Generate certificate then archive
        
        ```bash
        bash ./wazuh-certs-tool.sh -A
        ```
        
        ```bash
        tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
        ```
        
        ```bash
        rm -rf ./wazuh-certificates
        ```
        
- **Wazuh Node Indexer Installation**
    - Install dependencies package
        
        ```bash
        apt-get install debconf adduser procps
        ```
        
    - Install adds-on package
        
        ```bash
        apt-get install gnupg apt-transport-https
        ```
        
    - Install GPG key
        
        ```bash
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
        ```
        
    - Add repos
        
        ```bash
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
        ```
        
    - Update repos
        
        ```bash
        apt-get update
        ```
        
    - Install wazuh indexer
        
        ```bash
        apt-get -y install wazuh-indexer
        ```
        
    - Wazuh Indexer Configuration
        
        ```bash
        nano /etc/wazuh-indexer/opensearch.yml
        ```
        
        ***Focus on config.yml di /home/user/wazuh/certs***
        
        - `network.host` : fill with indexer node ip/hostname
        - `node.name` : fill with indexer node name
        - `cluster.initial_master_nodes, discovery.seed_hosts, plugins.security.nodes_dn` : just let it default 

- **Deploy Certificate**

    - Copy certificate
        
        ```bash
        mkdir /etc/wazuh-indexer/certs
        ```
        
        ```bash
        cp /home/ervikhan/wazuh/certs/wazuh-certificates.tar /etc/wazuh-indexer/certs
        ```
        
        ```bash
        tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
        ```
        
        ```bash
        mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
        ```
        
        ```bash
        mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
        ```
        
        ***node name is node indexer nama (becareful with that)***
        
    - File and owner modification
        
        ```bash
        chmod 500 /etc/wazuh-indexer/certs && chmod 400 /etc/wazuh-indexer/certs/*
        ```
        
    - Execute service
        
        ```bash
        systemctl daemon-reload
        systemctl enable wazuh-indexer
        systemctl start wazuh-indexer
        systemctl status wazuh-indexer
        ```
        
- **Cluster Initialization**

    - Run `indexer-security-init.sh`
        
        ```bash
        /usr/share/wazuh-indexer/bin/indexer-security-init.sh
        ```
        
- **Testing Wazuh Indexer**

    - With curl
        
        ```bash
        curl -k -u admin:admin https://<WAZUH_INDEXER_IP>:9200
        ```
        
    - With browser
        
        ```bash
        https://<WAZUH_INDEXER_IP>:9200
        ```
        
    - Check Node
        
        ```bash
        curl -k -u admin:admin https://<WAZUH_INDEXER_IP>:9200/_cat/nodes?v
        ```

<h3>Wazuh Manager/Wazuh Server Installation</h3>
- Node Installation
    - Install adds-on package
        
        ```bash
        apt-get install gnupg apt-transport-https
        ```
        
    - Impor GPG key
        
        ```bash
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
        ```
        
    - Add repos
        
        ```bash
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
        ```
        
    - Update repos
        
        ```bash
        apt update
        ```
        
        ***jika ada warning(bukan error), biasanya karena inisialisasi repository yang dilakukan lebih dari 1 kali, itu wajar***
        
    - Wazuh Manager/Server Installation
        
        ```bash
        apt-get -y install wazuh-manager
        ```
        
    - Execute service
        
        ```bash
        systemctl daemon-reload
        systemctl enable wazuh-manager
        systemctl start wazuh-manager
        systemctl status wazuh-manager
        ```
        
- Filebeat Installation
    - Install service
        
        ```bash
        apt-get -y install filebeat
        ```
        
    - Download `filebeat.yml`
        
        ```bash
        curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.3/tpl/wazuh/filebeat/filebeat.yml
        ```
        
    - Edit `filebeat.yml` change hosts with wazuh server/manager IP address
        
        ```bash
        nano /etc/filebeat/filebeat.yml
        ```
        
        ```bash
        # Wazuh - Filebeat configuration file
         output.elasticsearch:
         hosts: ["192.168.2.4:9200"]
         protocol: https
         username: ${username}
         password: ${password}
        ```
        
    - Create filebeat keystore
        
        ```bash
        filebeat keystore create
        ```
        
    - Create default username
        
        ```bash
        echo admin | filebeat keystore add username --stdin --force
        ```
        
        ```bash
        echo admin | filebeat keystore add password --stdin --force
        ```
        
    - Download alert template for wazuh indexer
        
        ```bash
        curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.3/extensions/elasticsearch/7.x/wazuh-template.json
        ```
        
        ```bash
        chmod go+r /etc/filebeat/wazuh-template.json
        ```
        
- Deploy Certificate
    - Copy `wazuh-certificates.tar` to /etc/filebeat/certs
        
        ```bash
        mkdir /etc/filebeat/certs
        ```
        
        ```bash
        cp /home/ervikhan/wazuh/certs/wazuh-certificates.tar /etc/filebeat/certs
        ```
        
    - Extract certification
        
        ```bash
        tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
        ```
        
        ```bash
        mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
        ```
        
        ```bash
        mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
        ```
        
        ***node name is wazuh server/manager name***
        
    - Exec privileges and owner
        
        ```bash
        chmod 500 /etc/filebeat/certs && chmod 400 /etc/filebeat/certs/*
        ```
        
        ```bash
        chown -R root:root /etc/filebeat/certs
        ```
        
    - Exec service
        
        ```bash
        systemctl daemon-reload
        systemctl enable filebeat
        systemctl start filebeat
        systemctl status filebeat
        ```
        
- Testing
    - Test filebeat
        
        ```bash
        filebeat test output
        ```
        
    - Output
        
        ```bash
        parse url... OK
          connection...
            parse host... OK
            dns lookup... OK
            addresses: 192.168.2.4
            dial up... OK
          TLS...
            security: server's certificate chain verification is enabled
            handshake... OK
            TLS version: TLSv1.3
            dial up... OK
          talk to server... OK
          version: 7.10.2
        ```

<h3>Wazuh Dashboard Installation</h3>
- Package Installation
    - Install Package Dependencies
        
        ```bash
        apt-get install debhelper tar curl libcap2-bin
        ```
        
    - Install adds-on package
        
        ```bash
        apt-get install gnupg apt-transport-https
        ```
        
    - Install GPG key
        
        ```bash
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
        ```
        
    - Add repos
        
        ```bash
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
        ```
        
    - update repos
        
        ```bash
        apt update
        ```
        
    - Install Wazuh Dashboard
        
        ```bash
        apt-get -y install wazuh-dashboard
        ```
        
- Wazuh Dashboard Installation
    - File Edit
        
        ```bash
        nano /etc/wazuh-dashboard/opensearch_dashboards.yml
        ```
        
        `server.host` : fill with 0.0.0.0 if allow all host IP
        
        `opensearch.hosts` : fill with wazih dashboard IP
        
        ```bash
        server.host: 0.0.0.0
           server.port: 443
           opensearch.hosts: https://192.168.2.4:9200
           opensearch.ssl.verificationMode: certificate
        ```
        
- Deploy Certificate
    - copy `wazuh-certificates.tar` to /etc/wazuh-dashboard/certs
        
        ```bash
        wazuh-certificates.tar
        ```
        
        ```bash
        cp /home/ervikhan/wazuh/certs/wazuh-certificates.tar /etc/wazuh-dashboard/certs
        ```
        
    - Extract certification files
        
        ```bash
        tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
        ```
        
        ```bash
        
        mv -n /etc/wazuh-dashboard/certs/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
        
        ```
        
        ```bash
        mv -n /etc/wazuh-dashboard/certs/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
        ```
        
        ***node name is wazuh dashboard node name***
        
    - Exec privileges and owner
        
        ```bash
        chmod 500 /etc/wazuh-dashboard/certs && chmod 400 /etc/wazuh-dashboard/certs/*
        ```
        
        ```bash
        chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
        ```
        
    - File edit
        
        ```bash
        nano /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
        ```
        
        ```bash
        hosts:
          - default:
            url: https://192.168.2.4
            port: 55000
            username: wazuh-wui
            password: wazuh-wui
            run_as: false
        ```
        
    - Exec service
        
        ```bash
        systemctl daemon-reload
        systemctl enable wazuh-dashboard
        systemctl start wazuh-dashboard
        systemctl status wazuh-dashboard
        ```
        
    - Restart wazih manager dan indexer
        
        ```bash
        systemctl restart wazuh-indexer
        systemctl restart wazuh-manager
        ```
        
- Testing
    - Open browser
        
        ```bash
        https://<wazuh-dashboard-ip>
        ```
        
        ***default username and password is admin admin***
        
    - For securing wazuh installation
        
        ```bash
        
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --change-all --admin-user wazuh --admin-password wazuh
        ```
        
    - Output
        
        ```bash
        INFO: The password for user admin is yWOzmNA.?Aoc+rQfDBcF71KZp?1xd7IO
        INFO: The password for user kibanaserver is nUa+66zY.eDF*2rRl5GKdgLxvgYQA+wo
        INFO: The password for user kibanaro is 0jHq.4i*VAgclnqFiXvZ5gtQq1D5LCcL
        INFO: The password for user logstash is hWW6U45rPoCT?oR.r.Baw2qaWz2iH8Ml
        INFO: The password for user readall is PNt5K+FpKDMO2TlxJ6Opb2D0mYl*I7FQ
        INFO: The password for user snapshotrestore is +GGz2noZZr2qVUK7xbtqjUup049tvLq.
        WARNING: Wazuh indexer passwords changed. Remember to update the password in the Wazuh dashboard and Filebeat nodes if necessary, and restart the services.
        INFO: The password for Wazuh API user wazuh is JYWz5Zdb3Yq+uOzOPyUU4oat0n60VmWI
        INFO: The password for Wazuh API user wazuh-wui is +fLddaCiZePxh24*?jC0nyNmgMGCKE+2
        INFO: Updated wazuh-wui user password in wazuh dashboard. Remember to restart the service.
        ```

<h3>Wazuh Agent Installation</h3>
Installed on Linux Ubuntu 20.04

- Install GPG key
    
    ```bash
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    ```
    
- Add repos
    
    ```bash
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    ```
    
- Update repos
    
    ```bash
    apt update
    ```
    
- Install wazuh agent
    
    ```bash
    WAZUH_MANAGER="*WAZUH_MANAGER_IP*" apt-get install wazuh-agent
    ```
    
- Exec service
    
    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    systemctl status wazuh-agent
    ```
    
- **Recommended action** (Disable Wazuh updates)
    
    ```bash
    sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
    ```
    
    ```bash
    apt-get update
    ```
    
    Alternatively, you can set the package state to `hold`
    This action stops updates but you can still upgrade it manually using `apt-get install`
    
    ```bash
    echo "wazuh-agent hold" | dpkg --set-selections
    ```
    
- Done, Automatically in the wazuh manager there will be a new agent when we have finished installing the wazuh agent on the host