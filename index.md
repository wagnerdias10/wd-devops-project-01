---
## 📋 DOCUMENT INFORMATION
**Author:** Wagner Dias  
**Project:** SSL Centralized Infrastructure  
**Repository:** https://github.com/wagnerdias10/ssl-centralizaed-infrastructure  
**License:** © 2025 Wagner - Documentation protected by copyright  
**Usage:** Allowed with mandatory attribution to original author

---

# 🚀 DEVOPS INFRASTRUCTURE PLATFORM SETUP GUIDE

## 📑 TABLE OF CONTENTS

### PART 1: BASE INFRASTRUCTURE
1. [Introduction & Philosophy](#introduction--philosophy)
2. [Technology Stack Overview](#technology-stack-overview)
3. [Prerequisites & Network Setup](#prerequisites--network-setup)
4. [Step-by-Step Infrastructure Implementation](#step-by-step-infrastructure-implementation)
5. [Infrastructure Verification](#infrastructure-verification)

### PART 2: APPLICATION PIPELINE & GITOPS
6. [Project Setup & Git Repositories](#project-setup--git-repositories)
7. [GitLab CI/CD Pipeline](#gitlab-cicd-pipeline)
8. [Kubernetes & ArgoCD Configuration](#kubernetes--argocd-configuration)
9. [Monitoring & Alerting](#monitoring--alerting)
10. [Failure Recovery & Rollback](#failure-recovery--rollback)
11. [Local Development Environment](#local-development-environment)
12. [Comprehensive Verification](#comprehensive-verification)

---

## PART 1: BASE INFRASTRUCTURE

## 🎯 INTRODUCTION & PHILOSOPHY

### 🔑 CORE PRINCIPLES
This enterprise-grade DevOps ecosystem is built with the following foundational principles:

- **🔒 Security First**: Ansible Vault for credentials, internal PKI for end-to-end HTTPS, zero-trust architecture
- **📖 Clarity & Understanding**: Detailed explanations transforming "how" into "why"
- **🛡️ Robustness & Idempotency**: Playbooks designed for multiple executions without side effects
- **💻 Developer Experience (DX)**: Smooth workflow from local development to production
- **🌐 End-to-End Vision**: Complete workflow coverage with production-grade monitoring

### 🔄 GitOps-Centric Workflow
The complete workflow follows GitOps principles where Git is the single source of truth:

```
Local Development → Commit & Push → GitLab CI/CD → ArgoCD → Kubernetes → Monitoring
```

**All passwords and IP addresses used in the guide are for illustrative purposes only and are no longer active.**

---

## 🛠️ TECHNOLOGY STACK OVERVIEW

### 🏗️ INFRASTRUCTURE COMPONENTS

| Component | Role | IP Address | Description |
|-----------|------|------------|-------------|
| 🖥️ VMware ESXi 8 | Hypervisor | N/A | Virtualization platform hosting all VMs |
| 🪟 Windows Server 2019 | DNS Server | 192.168.15.179 | Internal DNS for wd.local domain |
| 🐧 Ubuntu Server LTS | OS | Various | Stable base for all Linux VMs |
| ⚙️ Ansible | Automation | 192.168.204.153 | Configuration management and orchestration |
| 🔄 Nginx Reverse Proxy | Gateway | 192.168.204.146 | SSL termination, load balancing, PKI management |
| 📦 GitLab | SCM/CI/CD | 192.168.204.149 | Source control, pipelines, container registry |
| ☸️ K3s Kubernetes | Orchestration | 192.168.204.150 | Lightweight Kubernetes distribution |
| 🐄 Rancher | K8s Management | 192.168.204.130 | Cluster management interface |
| 🔍 SonarQube | Code Quality | 192.168.204.154 | Static analysis and security scanning |
| 🔄 ArgoCD | GitOps | K3s Cluster | Continuous deployment and synchronization |
| 📊 Prometheus | Monitoring | K3s Cluster | Metrics collection and alerting |
| 📈 Grafana | Visualization | K3s Cluster | Interactive dashboards and monitoring |
| 🐳 Docker Compose | Local Dev | Developer PC | Local environment simulation |

### 🌐 NETWORK TOPOLOGY

| VM Name | Main Function | IP Address |
|---------|---------------|------------|
| ansible-control | Ansible Control Machine | 192.168.204.153 |
| nginx | Nginx Reverse Proxy, PKI | 192.168.204.146 |
| gitlab | GitLab (SCM, CI/CD, Registry) | 192.168.204.149 |
| rancher | Rancher Management | 192.168.204.130 |
| k3s-master | K3s Control Plane | 192.168.204.150 |
| k3s-worker-01 | K3s Worker Node | 192.168.204.148 |
| k3s-worker-02 | K3s Worker Node | 192.168.204.151 |
| jenkins | Jenkins CI/CD | 192.168.204.147 |
| sonarqube | SonarQube Code Analysis | 192.168.204.154 |

---

## 📋 PREREQUISITES & NETWORK SETUP

### 🛠️ REQUIRED TOOLS
- VMware ESXi 8 configured and accessible
- Windows Server 2019 with DNS configured for wd.local domain
- MobaXTerm or VS Code with Remote-SSH extension
- Ubuntu Server 22.04 LTS ISO images

---

## 🚀 STEP-BY-STEP INFRASTRUCTURE IMPLEMENTATION

### 📝 STEP 1: Base VM Configuration (All VMs)

#### 1.1 VM Creation in ESXi 8
- Create VMs with recommended specifications:
  - **GitLab**: 4 vCPUs, 8GB RAM (min), 80GB disk
  - **Rancher**: 2 vCPUs, 4GB RAM
  - **SonarQube**: 2 vCPUs, 4GB RAM (8GB ideal)
  - **K3s Master**: 2 vCPUs, 4GB RAM
  - **K3s Workers**: 2 vCPUs, 4GB RAM each

#### 1.2 Post-Installation Configuration

**System update and essential tools installation:**
```bash
# System update and essential tools installation
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git vim net-tools
```

**Static IP configuration (Netplan):**
```yaml
# Netplan configuration example
network:
  ethernets:
    eth0:
      dhcp4: no
      addresses: [192.168.204.100/24]
      routes:
        - to: default
          via: 192.168.204.1
      nameservers:
        addresses: [192.168.15.179]
  version: 2
```

**Hostname and hosts file configuration:**
```bash
# Set hostname
sudo hostnamectl set-hostname <VM_NAME>

# Configure /etc/hosts
sudo nano /etc/hosts
```

### 🌐 STEP 2: DNS Configuration (Windows Server 2019)

#### 2.1 DNS Zone and Records
- Create forward lookup zone for `wd.local`
- Add host (A) records for all VMs
- Add wildcard record (*.wd.local) pointing to Nginx IP

**DNS verification:**
```bash
# Verify DNS resolution from Linux VMs
nslookup gitlab.wd.local
nslookup rancher.wd.local
nslookup anything.wd.local  # Should resolve to Nginx IP
```

### ⚙️ STEP 3: Ansible Control Machine Setup

#### 3.1 Ansible Installation and Configuration

**Ansible installation:**
```bash
# Install Ansible
sudo apt update
sudo apt install -y software-properties-common
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt install -y ansible
```

#### 3.2 SSH Key Distribution

**SSH key setup:**
```bash
# Generate SSH key pair
ssh-keygen -t rsa -b 4096 -C "ansible-key-wd"

# Copy public key to all VMs
ssh-copy-id -i ~/.ssh/id_rsa.pub wagner@192.168.204.146  # nginx
ssh-copy-id -i ~/.ssh/id_rsa.pub wagner@192.168.204.149  # gitlab
# Repeat for all other VMs...
```

### 📁 STEP 4: Ansible Project Structure Setup

#### 4.1 Directory Structure
```
~/ansible_devops_project/
+-- ansible.cfg
+-- inventory/
¦   +-- hosts
+-- group_vars/
¦   +-- all.yml
¦   +-- secrets.yml          # 🔐 Ansible Vault encrypted
+-- files/
¦   +-- wd-root-ca.crt
+-- templates/
¦   +-- *.j2                 # All Jinja2 templates
+-- playbooks/
    +-- 01_base_setup.yml
    +-- 02_nginx_pki_setup.yml
    +-- 03_gitlab_setup.yml
    +-- 04_k3s_cluster_setup.yml
    +-- 05_rancher_setup.yml
    +-- 06_argocd_setup.yml
    +-- 07_gitlab_runner_setup.yml
    +-- 08_jenkins_setup.yml
    +-- 09_sonarqube_setup.yml
    +-- 10_monitoring_setup.yml
```

#### 4.2 Configuration Files

**ansible.cfg:**
```ini
[defaults]
inventory = /home/wagnerdias/wd-devops-project-01/inventory.ini
remote_user = userone
ask_pass = false
private_key_file = ~/.ssh/id_rsa
host_key_checking = false
gathering = smart
fact_caching = jsonfile
fact_caching_connection = /tmp/ansible_facts_cache
fact_caching_timeout = 86400
stdout_callback = yaml
```

**inventory/hosts:**
```ini
[control_node]
ansible.wd.local ansible_host=192.168.204.153

[nginx_proxy]
nginx.wd.local ansible_host=192.168.204.146

[gitlab_server]
gitlab.wd.local ansible_host=192.168.204.149

[rancher_server]
rancher.wd.local ansible_host=192.168.204.130

[k3s_master]
k3s-master.wd.local ansible_host=192.168.204.150

[k3s_workers]
k3s-worker-01.wd.local ansible_host=192.168.204.148
k3s-worker-02.wd.local ansible_host=192.168.204.151

[sonarqube_server]
sonarqube.wd.local ansible_host=192.168.204.154

[jenkins_server]
jenkins.wd.local ansible_host=192.168.204.147
```

**group_vars/all.yml:**
```yaml
# Global configuration variables
internal_domain: "wd.local"
ansible_user: "wagnerdias"
ansible_become: true

# IP addresses for all VMs
ansible_control_ip: "192.168.204.153"
nginx_proxy_ip: "192.168.204.146"
gitlab_server_ip: "192.168.204.149"
rancher_server_ip: "192.168.204.130"
k3s_master_ip: "192.168.204.150"
k3s_worker_01_ip: "192.168.204.148"
k3s_worker_02_ip: "192.168.204.151"
sonarqube_server_ip: "192.168.204.154"
jenkins_server_ip: "192.168.204.147"

# PKI settings
pki_country: "BR"
pki_state: "Sao Paulo"
pki_organization: "WD Internal"
pki_common_name: "WD Internal Root CA"
pki_validity_days: 3650

# GitLab configuration
gitlab_external_url: "https://gitlab.wd.local"
gitlab_initial_root_password: "Lab@1234"

# K3s configuration
k3s_version: "v1.27.4+k3s1"
k3s_cluster_token: "supersecretclustertoken"

# Rancher configuration
rancher_version: "latest"
rancher_admin_password: "Lab@12345678"

# Monitoring configuration
grafana_admin_password: "Lab@1234"
```

**group_vars/secrets.yml:**
```yaml
# 🔐 Encrypted secrets - Use ansible-vault to create/edit
gitlab_root_password: "Lab@1234"
gitlab_pat_token: "glpat-xxxxxxxxxxxxxxxx"
rancher_admin_password: "Lab@12345678"
grafana_admin_password: "Lab@1234"
sonarqube_admin_password: "Lab@1234"
jenkins_admin_password: "Lab@1234"
```

### 🎯 STEP 5: Execute Playbooks in Order

#### 5.1 Base System Setup

playbooks/01_base_setup.yml

```yaml
# cd ~/ansible_devops_project
# ansible-playbook --ask-vault-pass playbooks/01_base_setup.yml

---
- name: Configurao Base Comum para Todas as VMs
  hosts: all_vms
  become: true
  gather_facts: false 

  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml 

  pre_tasks:
    - name: Aguardar que as VMs estejam acessveis via SSH
      ansible.builtin.wait_for_connection:
        timeout: 300 

    - name: Coletar fatos aps a conexo (necessrio para variveis como ansible_distribution_release)
      ansible.builtin.setup:

    - name: Garantir que o diretrio .ssh existe para o usurio Ansible
      ansible.builtin.file:
        path: "/home/{{ ansible_user }}/.ssh"
        state: directory
        mode: '0700'
        owner: "{{ ansible_user }}"
        group: "{{ ansible_user }}"

    - name: Distribuir chave pblica SSH do Ansible Control para authorized_keys (garante acesso idempotente)
      ansible.builtin.authorized_key:
        user: "{{ ansible_user }}"
        state: present
        key: "{{ lookup('file', ansible_ssh_private_key_file + '.pub') }}"
        manage_dir: true 

  tasks:
    - name: Atualizar cache de pacotes e fazer upgrade do sistema
      ansible.builtin.apt:
        update_cache: yes
        upgrade: dist
        autoclean: yes
        autoremove: yes
      register: apt_update_result
      until: apt_update_result is success 
      retries: 3
      delay: 5

    - name: Instalar ferramentas essenciais
      ansible.builtin.apt:
        name:
          - curl
          - wget
          - git
          - nano
          - tree
          - htop
          - net-tools
          - openssl
          - apt-transport-https
          - ca-certificates
          - software-properties-common
          - gnupg
          - lsb-release
          - python3-pip
          - python3-venv
          - python3-apt
        state: present

    - name: Configurar /etc/hosts para resoluo interna (idempotente)
      ansible.builtin.lineinfile:
        path: /etc/hosts
        regexp: |
              "^{{ item.ip }}\s+{{ item.hostname }}.*$" # regex para evitar duplicatas e permitir atualizaes
        line: "{{ item.ip }} {{ item.hostname }} {{ item.hostname.split('.')[0] }}"
        state: present
      loop:
        - { ip: "{{ ansible_control_ip }}", hostname: "ansible.{{ internal_domain }}" }
        - { ip: "{{ nginx_proxy_ip }}", hostname: "nginx.{{ internal_domain }}" }
        - { ip: "{{ gitlab_server_ip }}", hostname: "gitlab.{{ internal_domain }}" }
        - { ip: "{{ rancher_server_ip }}", hostname: "rancher.{{ internal_domain }}" }
        - { ip: "{{ k3s_master_ip }}", hostname: "k3s-master.{{ internal_domain }}" }
        - { ip: "{{ k3s_worker_01_ip }}", hostname: "k3s-worker-01.{{ internal_domain }}" }
        - { ip: "{{ k3s_worker_02_ip }}", hostname: "k3s-worker-02.{{ internal_domain }}" }
        - { ip: "{{ jenkins_server_ip }}", hostname: "jenkins.{{ internal_domain }}" }
        - { ip: "{{ sonarqube_server_ip }}", hostname: "sonarqube.{{ internal_domain }}" }

    - name: Configurar systemd-resolved para usar DNS interno e externo
      ansible.builtin.template:
        src: ../templates/resolved.conf.j2
        dest: /etc/systemd/resolved.conf
        mode: '0644'
      notify: Reiniciar systemd-resolved

    - name: Criar link simblico para resolv.conf (garante que systemd-resolved seja o provedor de DNS)
      ansible.builtin.file:
        src: /run/systemd/resolve/stub-resolv.conf
        dest: /etc/resolv.conf
        state: link
        force: true 
      notify: Reiniciar systemd-resolved

    - name: Desabilitar swap (essencial para Kubernetes)
      ansible.builtin.command: swapoff -a
      when: "'k3s_cluster' in group_names" 
      changed_when: false 

    - name: Remover entrada de swap do /etc/fstab (permanente)
      ansible.builtin.lineinfile:
        path: /etc/fstab
        regexp: '.*swap.*'
        state: absent
      when: "'k3s_cluster' in group_names"

    - name: Verificar se um reboot  necessrio (aps atualizaes de kernel, por exemplo)
      ansible.builtin.stat:
        path: /var/run/reboot-required
      register: reboot_required_file
      when: ansible_os_family == "Debian"

    - name: Reiniciar VMs (se necessrio)
      ansible.builtin.reboot:
        reboot_timeout: 600 
      when: reboot_required_file.stat.exists is defined and reboot_required_file.stat.exists

  handlers:
    - name: Reiniciar systemd-resolved
      ansible.builtin.systemd:
        name: systemd-resolved
        state: restarted
        daemon_reload: yes 
      listen: "Reiniciar systemd-resolved"

```

**What this does:**
- Updates system packages and installs essential tools
- Configures static IP addresses and hostnames
- Sets up DNS resolution and system limits
- Prepares all VMs for subsequent configurations

#### 5.2 NGINX and PKI Setup

playbooks/02_nginx_pki_setup.yml

```yaml
# ansible-playbook --ask-vault-pass playbooks/02_nginx_pki_setup.yml

- name: "Configurar NGINX Reverse Proxy e PKI Interna (Host: nginx)"
  hosts: nginx_proxy
  become: true
  gather_facts: true
  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml
  tasks:
    - name: Instalar NGINX
      ansible.builtin.apt:
        name: nginx
        state: present
        update_cache: true
    - name: Parar NGINX temporariamente para configuração
      ansible.builtin.systemd:
        name: nginx
        state: stopped
        enabled: false
    - name: Criar estrutura de diretórios para PKI e NGINX
      ansible.builtin.file:
        path: "{{ item.path }}"
        state: directory
        mode: "{{ item.mode | default('0755') }}"
        owner: "{{ item.owner | default('root') }}"
        group: "{{ item.group | default('root') }}"
      loop:
        - { path: "/etc/ssl/private/ca", mode: '0700' }
        - { path: "/etc/ssl/private/ca/newcerts" }
        - { path: "/etc/ssl/private/ca/certs" }
        - { path: "/etc/ssl/private/ca/crl" }
        - { path: "/etc/nginx/ssl", mode: '0700' }
        - { path: "/etc/nginx/sites-available" }
        - { path: "/etc/nginx/sites-enabled" }
        - { path: "/etc/nginx/conf.d" }
        - { path: "/var/log/nginx/sites" }
        - { path: "/opt/ssl-management/scripts" }
        - { path: "/opt/ssl-management/backups" }
        - { path: "/opt/ssl-management/templates" }
        - { path: "/var/cache/nginx/proxy", owner: 'www-data', group: 'www-data' }
    - name: Inicializar banco de dados da CA (index.txt e serial)
      ansible.builtin.file:
        path: "{{ item }}"
        state: touch
        mode: '0600'
      loop:
        - "/etc/ssl/private/ca/index.txt"
        - "/etc/ssl/private/ca/serial"
        - "/etc/ssl/private/ca/crlnumber"
    - name: Verificar estado do arquivo serial
      ansible.builtin.stat:
        path: "/etc/ssl/private/ca/serial"
      register: serial_file
    - name: Definir serial inicial para 1000 (se o arquivo não existir ou estiver vazio)
      ansible.builtin.copy:
        content: "1000"
        dest: "/etc/ssl/private/ca/serial"
        mode: '0644'
      when: not (serial_file.stat.exists and serial_file.stat.size > 0)
    - name: Verificar estado do arquivo crlnumber
      ansible.builtin.stat:
        path: "/etc/ssl/private/ca/crlnumber"
      register: crlnumber_file
    - name: Definir crlnumber inicial para 1000 (se o arquivo não existir ou estiver vazio)
      ansible.builtin.copy:
        content: "1000"
        dest: "/etc/ssl/private/ca/crlnumber"
        mode: '0644'
      when: not (crlnumber_file.stat.exists and crlnumber_file.stat.size > 0)
    - name: Criar arquivo de configuração da CA Raiz (openssl_root.cnf)
      ansible.builtin.template:
        src: ../templates/openssl_root.cnf.j2
        dest: /etc/ssl/private/ca/openssl_root.cnf
        mode: '0644'
    - name: Gerar chave privada e certificado da CA Raiz
      ansible.builtin.shell: |
        openssl req -x509 -new -nodes -newkey rsa:4096 -sha256 -days {{ pki_root_validity_days }} \
            -keyout /etc/ssl/private/ca/rootCA.key \
            -out /etc/ssl/private/ca/rootCA.crt \
            -config /etc/ssl/private/ca/openssl_root.cnf \
            -extensions v3_ca \
            -subj "/C={{ pki_country }}/ST={{ pki_state }}/L={{ pki_locality }}/O={{ pki_organization }}/OU={{ pki_organizational_unit }}/CN={{ pki_root_cn }}"
      args:
        creates: /etc/ssl/private/ca/rootCA.key
      changed_when: false
    - name: Definir permissões corretas para chave e certificado da CA Raiz
      ansible.builtin.file:
        path: "{{ item.path }}"
        mode: "{{ item.mode }}"
      loop:
        - { path: "/etc/ssl/private/ca/rootCA.key", mode: '0600' }
        - { path: "/etc/ssl/private/ca/rootCA.crt", mode: '0644' }
    - name: Criar arquivo de configuração da CA Intermediária (openssl_intermediate.cnf)
      ansible.builtin.template:
        src: ../templates/openssl_intermediate.cnf.j2
        dest: /etc/ssl/private/ca/openssl_intermediate.cnf
        mode: '0644'
    - name: Gerar chave privada e CSR da CA Intermediária
      ansible.builtin.shell: |
        openssl req -new -nodes -newkey rsa:4096 -sha256 \
            -keyout /etc/ssl/private/ca/intermediateCA.key \
            -out /etc/ssl/private/ca/intermediateCA.csr \
            -config /etc/ssl/private/ca/openssl_intermediate.cnf \
            -subj "/C={{ pki_country }}/ST={{ pki_state }}/L={{ pki_locality }}/O={{ pki_organization }}/OU={{ pki_organizational_unit }}/CN={{ pki_intermediate_cn }}"
      args:
        creates: /etc/ssl/private/ca/intermediateCA.key
      changed_when: false
    - name: Assinar o CSR da CA Intermediária com a CA Raiz
      ansible.builtin.shell: |
        openssl ca -batch \
            -in /etc/ssl/private/ca/intermediateCA.csr \
            -out /etc/ssl/private/ca/intermediateCA.crt \
            -days {{ pki_intermediate_validity_days }} \
            -config /etc/ssl/private/ca/openssl_root.cnf \
            -extensions v3_intermediate_ca \
            -rand_serial
      args:
        creates: /etc/ssl/private/ca/intermediateCA.crt
      changed_when: false
    - name: Definir permissões corretas para chave e certificado da CA Intermediária
      ansible.builtin.file:
        path: "{{ item.path }}"
        mode: "{{ item.mode }}"
      loop:
        - { path: "/etc/ssl/private/ca/intermediateCA.key", mode: '0600' }
        - { path: "/etc/ssl/private/ca/intermediateCA.crt", mode: '0644' }
    - name: Criar arquivo de configuração do Certificado Wildcard (wildcard_csr.cnf)
      ansible.builtin.template:
        src: ../templates/wildcard_csr.cnf.j2
        dest: /etc/nginx/ssl/wildcard_csr.cnf
        mode: '0644'
    - name: Gerar chave privada e CSR do certificado wildcard
      ansible.builtin.shell: |
        openssl req -new -nodes -newkey rsa:4096 -sha256 \
            -keyout /etc/nginx/ssl/wildcard.{{ internal_domain }}.key \
            -out /etc/nginx/ssl/wildcard.{{ internal_domain }}.csr \
            -config /etc/nginx/ssl/wildcard_csr.cnf \
            -subj "/C={{ pki_country }}/ST={{ pki_state }}/L={{ pki_locality }}/O={{ pki_organization }}/OU={{ pki_organizational_unit }}/CN={{ pki_wildcard_cn }}"
      args:
        creates: /etc/nginx/ssl/wildcard.{{ internal_domain }}.key
      changed_when: false
    - name: Assinar o CSR do certificado wildcard com a CA Intermediária
      ansible.builtin.shell: |
        openssl ca -batch \
            -in /etc/nginx/ssl/wildcard.{{ internal_domain }}.csr \
            -out /etc/nginx/ssl/wildcard.{{ internal_domain }}.crt \
            -days {{ pki_wildcard_validity_days }} \
            -config /etc/ssl/private/ca/openssl_intermediate.cnf \
            -extensions v3_wildcard_cert \
            -rand_serial
      args:
        creates: /etc/nginx/ssl/wildcard.{{ internal_domain }}.crt
      changed_when: false
    - name: Definir permissões corretas para chave e certificado wildcard
      ansible.builtin.file:
        path: "{{ item.path }}"
        mode: "{{ item.mode }}"
      loop:
        - { path: "/etc/nginx/ssl/wildcard.{{ internal_domain }}.key", mode: '0600' }
        - { path: "/etc/nginx/ssl/wildcard.{{ internal_domain }}.crt", mode: '0644' }
    - name: Criar cadeia de certificados completa (fullchain)
      ansible.builtin.shell: |
        cat /etc/nginx/ssl/wildcard.{{ internal_domain }}.crt \
            /etc/ssl/private/ca/intermediateCA.crt \
            /etc/ssl/private/ca/rootCA.crt \
            > /etc/nginx/ssl/wildcard_chain.crt
      args:
        creates: /etc/nginx/ssl/wildcard_chain.crt
      changed_when: false
    - name: Gerar parâmetros Diffie-Hellman
      ansible.builtin.shell: openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
      args:
        creates: /etc/nginx/ssl/dhparam.pem
      changed_when: false
    - name: Definir permissões corretas para dhparam.pem
      ansible.builtin.file:
        path: /etc/nginx/ssl/dhparam.pem
        mode: '0644'
    - name: Criar arquivo de configuração principal do NGINX (nginx.conf)
      ansible.builtin.template:
        src: ../templates/nginx.conf.j2
        dest: /etc/nginx/nginx.conf
        mode: '0644'
    - name: Criar arquivo de configuração de WebSocket
      ansible.builtin.template:
        src: ../templates/websocket.conf.j2
        dest: /etc/nginx/conf.d/websocket.conf
        mode: '0644'
    - name: Desabilitar site padrão do NGINX
      ansible.builtin.file:
        path: /etc/nginx/sites-enabled/default
        state: absent
      ignore_errors: true
    - name: Criar diretório para dashboard
      ansible.builtin.file:
        path: /var/www/dashboard
        state: directory
        mode: '0755'
        owner: www-data
        group: www-data
    - name: Criar página HTML do dashboard
      ansible.builtin.template:
        src: ../templates/dashboard_index.html.j2
        dest: /var/www/dashboard/index.html
        mode: '0644'
        owner: www-data
        group: www-data
    - name: Criar arquivo de configuração do dashboard
      ansible.builtin.template:
        src: ../templates/nginx_dashboard.conf.j2
        dest: "/etc/nginx/sites-available/dashboard.{{ internal_domain }}.conf"
        mode: '0644'
    - name: Habilitar site do dashboard
      ansible.builtin.file:
        src: "/etc/nginx/sites-available/dashboard.{{ internal_domain }}.conf"
        dest: "/etc/nginx/sites-enabled/dashboard.{{ internal_domain }}.conf"
        state: link
    - name: Criar configurações NGINX para serviços backend
      ansible.builtin.template:
        src: ../templates/nginx_service_template.conf.j2
        dest: "/etc/nginx/sites-available/{{ item.name }}.{{ internal_domain }}.conf"
        mode: '0644'
      loop:
        - { name: "gitlab", ip: "{{ gitlab_server_ip }}", port: "{{ gitlab_workhorse_port }}", registry_port: "{{ gitlab_registry_port }}" }
        - { name: "jenkins", ip: "{{ jenkins_server_ip }}", port: "{{ jenkins_internal_port }}" }
        - { name: "sonarqube", ip: "{{ sonarqube_server_ip }}", port: "{{ sonarqube_internal_port }}" }
        - { name: "rancher", ip: "{{ rancher_server_ip }}", port: "80" }
        - { name: "grafana", ip: "{{ k3s_master_ip }}", port: "3000" }
        - { name: "argocd", ip: "{{ k3s_master_ip }}", port: "8080" }
    - name: Habilitar configurações NGINX para backend
      ansible.builtin.file:
        src: "/etc/nginx/sites-available/{{ item.name }}.{{ internal_domain }}.conf"
        dest: "/etc/nginx/sites-enabled/{{ item.name }}.{{ internal_domain }}.conf"
        state: link
      loop:
        - { name: "gitlab" }
        - { name: "jenkins" }
        - { name: "sonarqube" }
        - { name: "rancher" }
        - { name: "grafana" }
        - { name: "argocd" }
    - name: Testar configuração do NGINX
      ansible.builtin.command: nginx -t
      register: nginx_test_result
      changed_when: false
      failed_when: nginx_test_result.rc != 0
      notify: Recarregar NGINX para aplicar as configurações
  handlers:
    - name: Recarregar NGINX para aplicar as configurações
      ansible.builtin.systemd:
        name: nginx
        state: reloaded
        enabled: true
      listen: "Recarregar NGINX para aplicar as configurações"
- name: Distribuir Root CA para o servidor Rancher
  hosts: rancher_standalone_server
  become: true
  gather_facts: true
  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml
  pre_tasks:
    - name: Aguardar que o Rancher esteja acessível via SSH
      ansible.builtin.wait_for_connection:
        timeout: 300
    - name: Recolher facts do Rancher
      ansible.builtin.setup:
  tasks:
    - name: Ler conteúdo do Root CA no nginx-proxy (slurp via nginx proxy)
      ansible.builtin.slurp:
        src: "/etc/ssl/private/ca/rootCA.crt"
      register: root_ca_content_slurp
      delegate_to: "{{ groups['nginx_proxy'][0] }}"
      become: false
    - name: Decodificar conteúdo do Root CA
      ansible.builtin.set_fact:
        root_ca_content_decoded: "{{ root_ca_content_slurp.content | b64decode }}"
    - name: Criar diretório para certificados confiáveis no Rancher Server
      ansible.builtin.file:
        path: /usr/local/share/ca-certificates/custom
        state: directory
        mode: '0755'
    - name: Copiar Root CA para Rancher
      ansible.builtin.copy:
        dest: /usr/local/share/ca-certificates/custom/rootCA.crt
        content: "{{ root_ca_content_decoded }}"
        mode: '0644'
    - name: Atualizar certificados CA no Rancher Server
      ansible.builtin.command: update-ca-certificates
      changed_when: true
- name: Distribuir Root CA para nós K3s
  hosts: k3s_cluster
  become: true
  gather_facts: true
  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml
  pre_tasks:
    - name: Aguardar que os nós K3s estejam acessíveis via SSH
      ansible.builtin.wait_for_connection:
        timeout: 300
    - name: Recolher facts dos nós K3s
      ansible.builtin.setup:
  tasks:
    - name: Ler conteúdo do Root CA no nginx-proxy (slurp via nginx proxy)
      ansible.builtin.slurp:
        src: "/etc/ssl/private/ca/rootCA.crt"
      register: root_ca_content_slurp_k
      delegate_to: "{{ groups['nginx_proxy'][0] }}"
      become: false
    - name: Decodificar conteúdo do Root CA (k3s)
      ansible.builtin.set_fact:
        root_ca_content_k: "{{ root_ca_content_slurp_k.content | b64decode }}"
    - name: Criar diretório para certificados confiáveis
      ansible.builtin.file:
        path: /usr/local/share/ca-certificates/custom
        state: directory
        mode: '0755'
    - name: Copiar Root CA para os nós K3s (usando conteúdo slurp)
      ansible.builtin.copy:
        dest: /usr/local/share/ca-certificates/custom/rootCA.crt
        content: "{{ root_ca_content_k }}"
        mode: '0644'
    - name: Atualizar certificados CA nos nós K3s
      ansible.builtin.command: update-ca-certificates
      changed_when: true
- name: Criar ConfigMap para Root CA no Kubernetes
  hosts: k3s_master
  become: false
  gather_facts: true
  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml
  pre_tasks:
    - name: Aguardar que o k3s master esteja acessível via SSH
      ansible.builtin.wait_for_connection:
        timeout: 300
    - name: Recolher facts do k3s master
      ansible.builtin.setup:
  tasks:
    - name: Ler conteúdo do Root CA no nginx-proxy
      ansible.builtin.slurp:
        src: "/etc/ssl/private/ca/rootCA.crt"
      register: root_ca_content_slurp_k8s
      delegate_to: "{{ groups['nginx_proxy'][0] }}"
      become: false
    - name: Decodificar conteúdo do Root CA
      ansible.builtin.set_fact:
        root_ca_content_k8s: "{{ root_ca_content_slurp_k8s.content | b64decode }}"
    - name: Definir caminho do kubeconfig no controlador Ansible
      ansible.builtin.set_fact:
        kubeconfig_path: "{{ ansible_controller_user_home | default(lookup('env', 'HOME')) }}/.kube/config"
      delegate_to: localhost
      run_once: true
      become: false
    - name: Criar ConfigMap com a Root CA (executado no controlador Ansible)
      delegate_to: localhost
      kubernetes.core.k8s: 
        state: present
        kubeconfig: "{{ kubeconfig_path }}"
        definition:
          apiVersion: v1
          kind: ConfigMap
          metadata:
            name: internal-ca-certificates
            namespace: default
          data:
            ca.crt: |
              {{ root_ca_content_k8s }}

```

**What this does:**
- Creates internal PKI (Root CA, Intermediate CA)
- Generates wildcard SSL certificate for `*.wd.local`
- Configures NGINX as reverse proxy with SSL termination
- Distributes Root CA to all systems

#### 5.3 GitLab Installation

playbooks/03_gitlab_setup.yml

```yaml
# ansible-playbook --ask-vault-pass playbooks/03_gitlab_setup.yml

- name: Instalar e Configurar GitLab
  hosts: gitlab_server
  become: true
  gather_facts: true

  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml  

  tasks:  
    - name: Instalar dependências do GitLab
      ansible.builtin.apt:
        name:
          - ca-certificates
          - curl
          - gnupg
          - lsb-release
        state: present

    - name: Adicionar chave GPG oficial do GitLab
      ansible.builtin.apt_key:
        url: https://packages.gitlab.com/gpg.key
        state: present

    - name: Adicionar repositório GitLab CE
      ansible.builtin.apt_repository:
        repo: "deb https://packages.gitlab.com/gitlab/gitlab-ce/ubuntu/ {{ ansible_distribution_release }} main"
        state: present
        filename: gitlab_gitlab-ce.list

    - name: Atualizar cache de pacotes após adicionar repositório GitLab
      ansible.builtin.apt:
        update_cache: yes

    - name: Instalar GitLab CE
      ansible.builtin.apt:
        name: gitlab-ce
        state: present
      register: gitlab_install_result
      until: gitlab_install_result is success
      retries: 5
      delay: 10
    
    - name: Criar diretório de backup para configuração do GitLab
      ansible.builtin.file:
        path: /etc/gitlab/backup
        state: directory
        mode: '0755'

    - name: Fazer backup do arquivo gitlab.rb original (se já existir)
      ansible.builtin.copy:
        src: /etc/gitlab/gitlab.rb
        dest: "/etc/gitlab/backup/gitlab.rb.orig-{{ ansible_date_time.iso8601_basic_short }}"
        remote_src: true
        force: false

    - name: Copiar configuração gitlab.rb ajustada para reverse proxy
      ansible.builtin.template:
        src: ../templates/gitlab.rb.j2
        dest: /etc/gitlab/gitlab.rb
        mode: '0600'
        force: true
      notify: Reconfigurar GitLab

    - name: Parar e desabilitar NGINX interno do GitLab (se estiver ativo)
      ansible.builtin.command: gitlab-ctl stop nginx && gitlab-ctl disable nginx
      args:
        warn: false
      changed_when: false
      failed_when: false

    - name: Criar diretório para certificados confiáveis do GitLab
      ansible.builtin.file:
        path: /etc/gitlab/trusted-certs
        state: directory
        mode: '0755'
      notify: Reconfigurar GitLab
    
    - name: Reconfigurar GitLab antes de obter a senha inicial
      ansible.builtin.command: gitlab-ctl reconfigure
      changed_when: false

    - name: Aguardar criação do arquivo de senha inicial do GitLab
      ansible.builtin.wait_for:
        path: /etc/gitlab/initial_root_password
        timeout: 180
        msg: "Arquivo de senha inicial do root ainda não foi criado pelo GitLab."
    
    - name: Obter senha inicial do root do GitLab
      ansible.builtin.shell: cat /etc/gitlab/initial_root_password
      register: gitlab_initial_root_password_output
      changed_when: false
      no_log: true

    - name: Exibir senha inicial do root do GitLab
      ansible.builtin.debug:
        msg: "🔐 A senha inicial do usuário 'root' do GitLab é: {{ gitlab_initial_root_password_output.stdout | default('Não encontrada ou já removida') }}"
      when: gitlab_initial_root_password_output.stdout | length > 0
  
  handlers:
    - name: Reconfigurar GitLab
      ansible.builtin.command: gitlab-ctl reconfigure
      args:
        warn: false

    - name: Reiniciar todos os serviços do GitLab após reconfiguração
      ansible.builtin.command: gitlab-ctl restart
      args:
        warn: false

    - name: Esperar GitLab Workhorse estar pronto na porta {{ gitlab_workhorse_port }}
      ansible.builtin.wait_for:
        port: "{{ gitlab_workhorse_port }}"
        host: "127.0.0.1"
        timeout: 300
        delay: 10
        state: started
        msg: "Timeout ao esperar o GitLab Workhorse responder."

```

**What this does:**
- Installs GitLab CE with external PostgreSQL
- Configures GitLab to work with NGINX reverse proxy
- Sets up Container Registry
- Displays initial root password

#### 5.4 K3s Kubernetes Cluster

playbooks/04_k3s_cluster_setup.yml

```yaml
# ansible-playbook --ask-vault-pass playbooks/04_k3s_cluster_setup.yml

- name: Configurar K3s Master
  hosts: k3s_master
  become: true
  gather_facts: true
  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml

  tasks:
    - name: Obter HOME do usuário no controlador Ansible
      ansible.builtin.set_fact:
        ansible_controller_user_home: "{{ lookup('env', 'HOME') }}"
      delegate_to: localhost
      run_once: true
      become: false

    - name: Instalar K3s Master (modo servidor com cluster-init e bind-address correto)
      ansible.builtin.shell: |
        curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --cluster-init --bind-address={{ k3s_master_ip }}" sh -
      args:
        creates: /usr/local/bin/k3s 
      register: k3s_master_install_result
      changed_when: k3s_master_install_result.rc != 0

    - name: Esperar K3s Master iniciar (porta 6443)
      ansible.builtin.wait_for:
        port: 6443
        host: "{{ ansible_host }}"
        timeout: 300
        state: started
        msg: "Timeout ao esperar o K3s Master responder na porta 6443."

    - name: Obter K3s join token do Master
      ansible.builtin.shell: cat /var/lib/rancher/k3s/server/node-token
      register: k3s_node_token_raw
      delegate_to: "{{ inventory_hostname }}"
      run_once: true
      no_log: true

    - name: Salvar K3s join token para uso posterior (variável de fato)
      ansible.builtin.set_fact:
        k3s_token: "{{ k3s_node_token_raw.stdout }}"

    - name: Instalar kubectl no Master
      ansible.builtin.shell: |
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
      args:
        creates: /usr/local/bin/kubectl
      register: kubectl_install_result
      changed_when: kubectl_install_result.rc != 0

    - name: Instalar Helm no Master
      ansible.builtin.shell: |
        curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
        chmod 700 get_helm.sh
        ./get_helm.sh
      args:
        creates: /usr/local/bin/helm
      register: helm_install_result
      changed_when: helm_install_result.rc != 0

    - name: Criar diretório de configuração para K3s (se não existir)
      ansible.builtin.file:
        path: /etc/rancher/k3s
        state: directory
        mode: '0755'

    - name: Criar arquivo de configuração de registries para K3s (para o GitLab Container Registry)
      ansible.builtin.template:
        src: ../templates/k3s_registries.yaml.j2
        dest: /etc/rancher/k3s/registries.yaml
        mode: '0644'
      notify: Reiniciar K3s Master 

    - name: Criar diretório /etc/kubernetes/ssl/certs
      ansible.builtin.file:
        path: "/etc/kubernetes/ssl/certs"
        state: directory
        mode: '0755'
        owner: root
        group: root

    - name: Criar link simbólico para server-ca.crt no caminho esperado pelo cattle-cluster-agent
      ansible.builtin.file:
        src: "/var/lib/rancher/k3s/server/tls/server-ca.crt" 
        dest: "/etc/kubernetes/ssl/certs/serverca"          
        state: link
        force: yes
      notify: Reiniciar K3s Master 
    
    - name: Garantir diretório .kube no controlador Ansible
      ansible.builtin.file:
        path: "{{ ansible_controller_user_home }}/.kube"
        state: directory
        mode: '0700'
        owner: "{{ ansible_user }}"
        group: "{{ ansible_user }}"
      delegate_to: localhost
      run_once: true
      become: false

    - name: Ler conteúdo do kubeconfig no K3s Master
      ansible.builtin.slurp:
        src: /etc/rancher/k3s/k3s.yaml
      register: k3s_kubeconfig_slurp
      delegate_to: "{{ inventory_hostname }}" 

    - name: Substituir 127.0.0.1 pelo IP do K3s Master no conteúdo do kubeconfig
      ansible.builtin.set_fact:
        k3s_kubeconfig_content_modified: "{{ (k3s_kubeconfig_slurp.content | b64decode) | regex_replace('127\\.0\\.0\\.1', k3s_master_ip) }}"

    - name: Salvar kubeconfig modificado no controlador Ansible
      ansible.builtin.copy:
        content: "{{ k3s_kubeconfig_content_modified }}"
        dest: "{{ ansible_controller_user_home }}/.kube/config"
        mode: '0600'
        owner: "{{ ansible_user }}"
        group: "{{ ansible_user }}"
      delegate_to: localhost
      run_once: true
      become: false

  handlers:
    - name: Reiniciar K3s Master
      ansible.builtin.systemd:
        name: k3s
        state: restarted
        daemon_reload: yes
      listen: "Reiniciar K3s Master"

- name: Configurar K3s Workers
  hosts: k3s_workers
  become: true
  gather_facts: true
  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml

  tasks:
    - name: Instalar K3s Worker
      ansible.builtin.shell: |
        curl -sfL https://get.k3s.io | K3S_URL="https://{{ k3s_master_ip }}:6443" K3S_TOKEN="{{ hostvars[groups['k3s_master'][0]].k3s_token }}" sh -
      args:
        creates: /usr/local/bin/k3s 
      register: k3s_worker_install_result
      changed_when: k3s_worker_install_result.rc != 0

    - name: Instalar kubectl nos Workers
      ansible.builtin.shell: |
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
      args:
        creates: /usr/local/bin/kubectl
      register: kubectl_worker_install_result
      changed_when: kubectl_worker_install_result.rc != 0

    - name: Instalar Helm nos Workers
      ansible.builtin.shell: |
        curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
        chmod 700 get_helm.sh
        ./get_helm.sh
      args:
        creates: /usr/local/bin/helm
      register: helm_worker_install_result
      changed_when: helm_worker_install_result.rc != 0

    - name: Criar diretório de configuração para K3s (se não existir)
      ansible.builtin.file:
        path: /etc/rancher/k3s
        state: directory
        mode: '0755'

    - name: Criar arquivo de configuração de registries para K3s (para o GitLab Container Registry)
      ansible.builtin.template:
        src: ../templates/k3s_registries.yaml.j2
        dest: /etc/rancher/k3s/registries.yaml
        mode: '0644'
      notify: Reiniciar K3s Worker

  handlers:
    - name: Reiniciar K3s Worker
      ansible.builtin.systemd:
        name: k3s-agent
        state: restarted
        daemon_reload: yes
      listen: "Reiniciar K3s Worker"

```

**What this does:**
- Installs K3s master with cluster-init mode
- Joins worker nodes to the cluster
- Configures kubectl and Helm on all nodes
- Sets up GitLab Container Registry integration

#### 5.5 Rancher Management

playbooks/05_rancher_setup.yml

```yaml
# ansible-playbook --ask-vault-pass playbooks/05_rancher_setup.yml

- name: Instalar e Configurar Rancher Standalone via Docker
  hosts: rancher_standalone_server
  become: true
  gather_facts: true

  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml

  tasks:    
    - name: Instalar Docker e dependências
      ansible.builtin.apt:
        name:
          - docker.io
          - docker-compose
          - python3-pip
          - python3-venv
        update_cache: yes
        state: present

    - name: Instalar Docker SDK para Python
      ansible.builtin.pip:
        name: docker
        state: present
        virtualenv: /opt/ansible_venv/docker_sdk
        virtualenv_command: python3 -m venv

    - name: Iniciar e habilitar Docker
      ansible.builtin.systemd:
        name: docker
        state: started
        enabled: yes

    - name: Adicionar usuário ao grupo docker
      ansible.builtin.user:
        name: "{{ ansible_user }}"
        groups: docker
        append: yes
      changed_when: false
    
    - name: Criar diretório para armazenar a CA usada pelo Rancher
      ansible.builtin.file:
        path: /opt/rancher/certs
        state: directory
        mode: '0755'

    - name: Copiar CA interna para o host (para ser montada no container)
      ansible.builtin.copy:
        src: ../files/wd-root-ca.crt
        dest: /opt/rancher/certs/cacerts.pem
        mode: '0644'
    
    - name: Remover flag de reset (se existir)
      ansible.builtin.file:
        path: /opt/rancher/server/db/reset-flag
        state: absent
      changed_when: false

    - name: Remover container antigo do Rancher
      community.docker.docker_container:
        name: rancher
        state: absent
    
    - name: Subir Rancher usando a CA fornecida
      community.docker.docker_container:
        name: rancher
        image: rancher/rancher:stable
        state: started
        privileged: true
        restart_policy: unless-stopped
        ports:
          - "80:80"
        volumes:
          - /opt/rancher:/var/lib/rancher
          - /opt/rancher/certs/cacerts.pem:/etc/rancher/ssl/cacerts.pem:ro
        env:
          CATTLE_SERVER_URL: "https://rancher.{{ internal_domain }}"
          CATTLE_BOOTSTRAP_PASSWORD: "{{ rancher_admin_password }}"
      register: rancher_start_status

    - name: Exibir status da criação do container Rancher
      ansible.builtin.debug:
        var: rancher_start_status
    
    - name: Aguardar Rancher responder
      ansible.builtin.wait_for:
        host: "{{ ansible_host }}"
        port: 80
        timeout: 600
        delay: 10
        state: started
    
    - name: Exibir URL final do Rancher
      ansible.builtin.debug:
        msg: >
          Rancher instalado e acessível em https://rancher.{{ internal_domain }}
          Senha inicial: {{ rancher_admin_password }}

```

**What this does:**
- Deploys Rancher via Docker container
- Configures with internal CA certificates
- Sets up initial admin password

#### 5.6 ArgoCD GitOps

playbooks/06_argocd_setup.yml

```yaml
# ansible-playbook --ask-vault-pass playbooks/06_argocd_setup.yml

- name: Instalar e Configurar ArgoCD
  hosts: k3s_master
  become: true

  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml

  tasks:
    - name: Instalar coleo community.kubernetes (se ainda no instalada)
      ansible.builtin.command: ansible-galaxy collection install community.kubernetes
      ignore_errors: true

    - name: Criar namespace para ArgoCD (se no existir)
      community.kubernetes.k8s:
        name: argocd
        api_version: v1
        kind: Namespace
        state: present
      register: argocd_namespace_result
      changed_when: argocd_namespace_result.stdout is search("created")

    - name: Instalar ArgoCD com manifests oficiais (aplicar apenas se ainda no estiver instalado)
      ansible.builtin.uri:
        url: https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
        return_content: true
      register: argocd_install_manifest

    - name: Aplicar manifests do ArgoCD
      community.kubernetes.k8s:
        state: present
        definition: "{{ argocd_install_manifest.content }}"
        namespace: argocd
      register: argocd_apply_result
      changed_when: argocd_apply_result.changed

    - name: Aguardar pods do ArgoCD estarem prontos
      community.kubernetes.k8s_info:
        api_version: v1
        kind: Pod
        namespace: argocd
        label_selector: "app.kubernetes.io/name=argocd-server"
        wait: true
        wait_condition:
          type: Ready
          status: "True"
        wait_timeout: 300 
      register: argocd_pods_ready_check
      until: argocd_pods_ready_check.resources | length > 0 and argocd_pods_ready_check.resources[0].status.conditions | selectattr('type', 'equalto', 'Ready') | map(attribute='status') | first == 'True'
      retries: 6
      delay: 5

    - name: Obter senha inicial do admin do ArgoCD
      ansible.builtin.shell: kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
      register: argocd_initial_password
      changed_when: false
      no_log: true 

    - name: Exibir senha inicial do ArgoCD
      ansible.builtin.debug:
        msg: "✅ Senha inicial do ArgoCD para o usurio 'admin' (para login via CLI/UI) : {{ argocd_initial_password.stdout }}"
      when: argocd_initial_password.stdout is defined and argocd_initial_password.stdout != ''

    - name: Mudar tipo de servio argocd-server para NodePort (para acesso externo via Nginx)
      community.kubernetes.k8s:
        api_version: v1
        kind: Service
        name: argocd-server
        namespace: argocd
        state: present
        definition:
          spec:
            type: NodePort
            ports:
              - port: 443
                targetPort: 8080
                nodePort: 30080 
      register: argocd_svc_patch_result
      changed_when: argocd_svc_patch_result.changed

    - name: Obter porta NodePort do ArgoCD
      ansible.builtin.shell: kubectl get svc argocd-server -n argocd -o jsonpath='{.spec.ports[?(@.port==443)].nodePort}'
      register: argocd_nodeport_dynamic
      changed_when: false

    - name: Exibir porta NodePort do ArgoCD (para verificacao)
      ansible.builtin.debug:
        msg: "ArgoCD NodePort: {{ argocd_nodeport_dynamic.stdout }}"

    - name: Adicionar credenciais do repositrio GitLab ao ArgoCD (via CLI interna no Master)
      ansible.builtin.shell: |
        argocd repo add https://gitlab.{{ internal_domain }}/{{ gitlab_pat_username }}/gitops-repo.git \
          --username {{ gitlab_pat_username }} \
          --password {{ gitlab_pat_token }} \
          --insecure-skip-tls-verify \
          --name gitlab-gitops-repo \
          --grpc-web # Usar grpc-web para compatibilidade com Nginx
      environment:
        ARGOCD_SERVER: "localhost:8080" 
        ARGOCD_AUTH_TOKEN: "{{ argocd_initial_password.stdout }}" 
      args:
        chdir: "/usr/local/bin" 
      changed_when: true 
      no_log: true
      ignore_errors: yes 

    - name: Instalar argocd CLI no Master (se ainda no instalado)
      ansible.builtin.shell: |
        curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
        sudo install -m 555 argocd-linux-amd64 /usr/local/bin/argocd
        rm argocd-linux-amd64
      args:
        creates: /usr/local/bin/argocd

```

**What this does:**
- Deploys ArgoCD to K3s cluster
- Configures GitLab repository integration
- Sets up NodePort service for external access

#### 5.7 GitLab Runner

playbooks/07_gitlab_runner_setup.yml

```yaml
# ansible-playbook --ask-vault-pass playbooks/07_gitlab_runner_setup.yml

- name: Instalar e Configurar GitLab Runner no Kubernetes
  hosts: k3s_master
  become: yes

  vars:
    gitlab_url: "https://gitlab.wd.local"
    gitlab_runner_namespace: "gitlab-runner"
    runner_registration_token: "glrt-FHxBHzgrA8ZGmikMKv39Dm86MQp0OjEKdToyCw.01.120f67uph"
    gitlab_ca_cert_local: "{{ playbook_dir }}/../files/wd-root-ca.crt"

  tasks:
    - name: Exibir caminho do certificado (debug)
      ansible.builtin.debug:
        msg: "Procurando certificado em: {{ gitlab_ca_cert_local }}"

    - name: Verificar se certificado CA existe localmente
      ansible.builtin.stat:
        path: "{{ gitlab_ca_cert_local }}"
      delegate_to: localhost
      register: ca_cert_check
      become: no

    - name: Exibir resultado da verificação (debug)
      ansible.builtin.debug:
        msg: "Certificado existe: {{ ca_cert_check.stat.exists }}"

    - name: Falhar se certificado não existir
      ansible.builtin.fail:
        msg: "Certificado CA não encontrado em {{ gitlab_ca_cert_local }}"
      when: not ca_cert_check.stat.exists

    - name: Verificar se Helm está instalado
      ansible.builtin.command: helm version --short
      register: helm_check
      changed_when: false
      failed_when: false

    - name: Instalar Helm se necessário
      ansible.builtin.shell: |
        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
      args:
        creates: /usr/local/bin/helm
      when: helm_check.rc != 0

    - name: Verificar biblioteca Python kubernetes
      ansible.builtin.command: python3 -c "import kubernetes"
      register: k8s_lib_check
      changed_when: false
      failed_when: false

    - name: Instalar/Atualizar biblioteca kubernetes
      ansible.builtin.pip:
        name: kubernetes>=24.2.0
        executable: pip3
        state: present
      when: k8s_lib_check.rc != 0

    - name: Adicionar repositório Helm do GitLab
      kubernetes.core.helm_repository:
        name: gitlab
        repo_url: https://charts.gitlab.io
        state: present
      environment:
        KUBECONFIG: /etc/rancher/k3s/k3s.yaml

    - name: Atualizar repositórios Helm
      ansible.builtin.command: helm repo update
      environment:
        KUBECONFIG: /etc/rancher/k3s/k3s.yaml
      changed_when: true

    - name: Criar namespace gitlab-runner
      kubernetes.core.k8s:
        name: "{{ gitlab_runner_namespace }}"
        api_version: v1
        kind: Namespace
        state: present
        kubeconfig: /etc/rancher/k3s/k3s.yaml

    - name: Criar Secret com certificado CA do GitLab
      kubernetes.core.k8s:
        state: present
        kubeconfig: /etc/rancher/k3s/k3s.yaml
        definition:
          apiVersion: v1
          kind: Secret
          metadata:
            name: gitlab-ca-cert
            namespace: "{{ gitlab_runner_namespace }}"
          type: Opaque
          stringData:
            gitlab.wd.local.crt: "{{ lookup('file', gitlab_ca_cert_local) }}"

    - name: Exibir confirmação de certificado
      ansible.builtin.debug:
        msg: "✅ Certificado CA carregado de {{ gitlab_ca_cert_local }}"

    - name: Exibir informações de instalação
      ansible.builtin.debug:
        msg:
          - "=========================================="
          - "📋 INSTALANDO GITLAB RUNNER"
          - "=========================================="
          - "GitLab URL: {{ gitlab_url }}"
          - "Namespace: {{ gitlab_runner_namespace }}"
          - "Token: {{ runner_registration_token[:15] }}..."
          - "Certificado CA: {{ gitlab_ca_cert_local }}"
          - "=========================================="

    - name: Deploy GitLab Runner via Helm
      kubernetes.core.helm:
        name: gitlab-runner
        chart_ref: gitlab/gitlab-runner
        release_namespace: "{{ gitlab_runner_namespace }}"
        create_namespace: no
        kubeconfig: /etc/rancher/k3s/k3s.yaml
        update_repo_cache: yes
        wait: yes
        wait_timeout: 10m
        values:
          gitlabUrl: "{{ gitlab_url }}"
          runnerToken: "{{ runner_registration_token }}"
          certsSecretName: gitlab-ca-cert
          rbac:
            create: true

          runners:
            config: |
              [[runners]]
                [runners.kubernetes]
                  namespace = "{{ gitlab_runner_namespace }}"
                  image = "ubuntu:22.04"
                  privileged = true

                  [[runners.kubernetes.volumes.empty_dir]]
                    name = "docker-certs"
                    mount_path = "/certs/client"
                    medium = "Memory"

            privileged: true
            tags: "k3s,docker,kubernetes"
            runUntagged: false
            locked: false

          resources:
            limits:
              memory: 256Mi
              cpu: 200m
            requests:
              memory: 128Mi
              cpu: 100m
      register: helm_deploy

    - name: Exibir status da instalação
      ansible.builtin.debug:
        msg: "{{ '✅ GitLab Runner instalado com sucesso!' if not helm_deploy.failed else '❌ Falha na instalação' }}"

    - name: Aguardar 30 segundos para runner iniciar
      ansible.builtin.pause:
        seconds: 30

    - name: Listar pods do GitLab Runner
      ansible.builtin.command: kubectl get pods -n {{ gitlab_runner_namespace }}
      environment:
        KUBECONFIG: /etc/rancher/k3s/k3s.yaml
      register: runner_pods_list
      changed_when: false

    - name: Exibir pods criados
      ansible.builtin.debug:
        msg: "{{ runner_pods_list.stdout_lines }}"

    - name: Obter logs do runner
      ansible.builtin.shell: |
        kubectl logs -n {{ gitlab_runner_namespace }} \
          -l app=gitlab-runner \
          --tail=100 \
      register: runner_logs
      changed_when: false

    - name: Exibir logs do runner
      ansible.builtin.debug:
        msg: "{{ runner_logs.stdout_lines }}"

    - name: Verificar se há erros de certificado nos logs
      ansible.builtin.set_fact:
        cert_error_found: "{{ 'x509' in runner_logs.stdout or 'certificate' in runner_logs.stdout }}"

    - name: Alerta se ainda houver erro de certificado
      ansible.builtin.debug:
        msg: "⚠️ ATENÇÃO: Ainda há menções a certificado nos logs. Verifique manualmente."
      when: cert_error_found

    - name: Confirmação se não houver erro de certificado
      ansible.builtin.debug:
        msg: "✅ Nenhum erro de certificado detectado nos logs!"
      when: not cert_error_found

    - name: Exibir informações finais
      ansible.builtin.debug:
        msg:
          - "=========================================="
          - "✅ GITLAB RUNNER CONFIGURADO!"
          - "=========================================="
          - ""
          - "📋 INFORMAÇÕES:"
          - "  Namespace: {{ gitlab_runner_namespace }}"
          - "  GitLab URL: {{ gitlab_url }}"
          - "  Certificado CA: ✅ Configurado"
          - "  Tags: k3s, docker, kubernetes"
          - ""
          - "🔍 VERIFICAR REGISTRO:"
          - "  1. Acesse: {{ gitlab_url }}/admin/runners"
          - "  2. Procure por runner com tags: k3s, docker, kubernetes"
          - "  3. Status deve ser: 'online' (verde)"
          - ""
          - "📝 COMANDOS ÚTEIS:"
          - "  kubectl get pods -n {{ gitlab_runner_namespace }}"
          - "  kubectl logs -n {{ gitlab_runner_namespace }} -l app=gitlab-runner -f"
          - "  kubectl describe pod -n {{ gitlab_runner_namespace }} <pod-name>"
          - ""
          - "=========================================="

```

**What this does:**
- Deploys GitLab Runner to Kubernetes
- Configures with internal CA certificates
- Registers runner with GitLab instance

#### 5.8 Jenkins CI/CD

playbooks/08_jenkins_setup.yml

```yaml
# ansible-playbook --ask-vault-pass playbooks/08_jenkins_setup.yml

- name: Instalar e Configurar Jenkins
  hosts: jenkins_server
  become: true
  gather_facts: true

  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml

  tasks:
    - name: Instalar dependências do Jenkins
      ansible.builtin.apt:
        name:
          - openjdk-17-jdk
          - ca-certificates
          - curl
          - gnupg
          - software-properties-common
        state: present

    - name: Criar diretório para chaves GPG
      ansible.builtin.file:
        path: /etc/apt/keyrings
        state: directory
        mode: '0755'

    - name: Baixar e instalar chave GPG do Jenkins (método moderno)
      ansible.builtin.shell:
        cmd: |
          curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | gpg --dearmor -o /etc/apt/keyrings/jenkins.gpg
        creates: /etc/apt/keyrings/jenkins.gpg

    - name: Adicionar repositório Jenkins Stable
      ansible.builtin.apt_repository:
        repo: "deb [signed-by=/etc/apt/keyrings/jenkins.gpg] https://pkg.jenkins.io/debian-stable binary/"
        state: present
        filename: jenkins

    - name: Atualizar cache de pacotes após adicionar repositório Jenkins
      ansible.builtin.apt:
        update_cache: yes
        cache_valid_time: 3600

    - name: Instalar Jenkins
      ansible.builtin.apt:
        name: jenkins
        state: present
        update_cache: yes
      register: jenkins_install_result
      until: jenkins_install_result is success
      retries: 5
      delay: 10

    - name: Aguardar serviço Jenkins estar disponível
      ansible.builtin.systemd:
        name: jenkins
        state: started
        enabled: yes

    - name: Criar diretório de backup para configuração do Jenkins
      ansible.builtin.file:
        path: /etc/default/backup
        state: directory
        mode: '0755'

    - name: Fazer backup do arquivo de configuração padrão do Jenkins
      ansible.builtin.copy:
        src: /etc/default/jenkins
        dest: /etc/default/backup/jenkins.orig-{{ ansible_date_time.iso8601_basic_short }}
        remote_src: true
        force: false
      check_mode: false

    - name: Configurar Jenkins para usar NGINX Reverse Proxy
      ansible.builtin.lineinfile:
        path: /etc/default/jenkins
        regexp: '^JENKINS_PORT='
        line: 'JENKINS_PORT={{ jenkins_internal_port }}'
        state: present
      notify: Reiniciar Jenkins

    - name: Configurar HTTP_PORT
      ansible.builtin.lineinfile:
        path: /etc/default/jenkins
        regexp: '^HTTP_PORT='
        line: 'HTTP_PORT={{ jenkins_internal_port }}'
        state: present
      notify: Reiniciar Jenkins

    - name: Configurar JENKINS_ARGS para proxy reverso
      ansible.builtin.lineinfile:
        path: /etc/default/jenkins
        regexp: '^JENKINS_ARGS='
        line: 'JENKINS_ARGS="--webroot=/var/cache/jenkins/war --httpListenAddress=127.0.0.1 --httpPort={{ jenkins_internal_port }} --prefix=/jenkins"'
        state: present
      notify: Reiniciar Jenkins

    - name: Configurar Jenkins para aceitar proxy reverso
      ansible.builtin.lineinfile:
        path: /etc/default/jenkins
        regexp: '^JENKINS_PREFIX='
        line: 'JENKINS_PREFIX=/jenkins'
        state: present
      notify: Reiniciar Jenkins

    - name: Criar diretório para configurações extras
      ansible.builtin.file:
        path: /var/lib/jenkins/init.groovy.d
        state: directory
        owner: jenkins
        group: jenkins
        mode: '0755'

    - name: Configurar admin password via Groovy (método alternativo)
      ansible.builtin.copy:
        dest: /var/lib/jenkins/init.groovy.d/security.groovy
        content: |
          #!groovy

          import jenkins.model.*
          import hudson.security.*
          import hudson.util.*
          import jenkins.install.InstallState

          def instance = Jenkins.getInstance()

          // Skip setup wizard if not configured
          if (instance.getInstallState() == InstallState.UNKNOWN) {
            instance.setInstallState(InstallState.INITIAL_SETUP_COMPLETED)
          }

          // Create the user with password if security is not configured
          if (!instance.isUseSecurity()) {
            def hudsonRealm = new HudsonPrivateSecurityRealm(false)
            hudsonRealm.createAccount("admin", "{{ jenkins_admin_password }}")
            instance.setSecurityRealm(hudsonRealm)

            def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
            instance.setAuthorizationStrategy(strategy)
            instance.save()
          }
        owner: jenkins
        group: jenkins
        mode: '0644'
      notify: Reiniciar Jenkins

    - name: Garantir que Jenkins escute apenas em localhost
      ansible.builtin.lineinfile:
        path: /etc/default/jenkins
        regexp: '^JENKINS_LISTEN_ADDRESS='
        line: 'JENKINS_LISTEN_ADDRESS=127.0.0.1'
        state: present
      notify: Reiniciar Jenkins

    - name: Ajustar limites de sistema para Jenkins
      ansible.builtin.blockinfile:
        path: "/etc/security/limits.conf"
        block: |
          jenkins    -    nofile    8192
          jenkins    -    nproc     4096
        marker: "# {mark} ANSIBLE MANAGED BLOCK FOR JENKINS LIMITS"

    - name: Aguardar Jenkins inicializar completamente
      ansible.builtin.wait_for:
        port: "{{ jenkins_internal_port }}"
        host: 127.0.0.1
        state: started
        timeout: 120
        delay: 10

    - name: Verificar status do serviço Jenkins
      ansible.builtin.systemd:
        name: jenkins
        state: started
      register: jenkins_service_status

    - name: Verificar processo Jenkins
      ansible.builtin.shell:
        cmd: ps aux | grep jenkins | grep -v grep
      register: jenkins_process
      changed_when: false

    - name: Verificar porta Jenkins
      ansible.builtin.wait_for:
        port: "{{ jenkins_internal_port }}"
        host: 127.0.0.1
        state: started
        timeout: 30

    - name: Testar acesso local ao Jenkins
      ansible.builtin.uri:
        url: "http://127.0.0.1:{{ jenkins_internal_port }}/jenkins"
        method: GET
        status_code: 200, 403, 503
        timeout: 30
      register: jenkins_local_test
      ignore_errors: yes

    - name: Obter initial admin password (se aplicável)
      ansible.builtin.shell:
        cmd: cat /var/lib/jenkins/secrets/initialAdminPassword
      register: jenkins_initial_password
      ignore_errors: yes
      changed_when: false

    - name: Mostrar resultado da instalação
      ansible.builtin.debug:
        msg: |
          🎉 JENKINS INSTALADO COM SUCESSO!
          =================================
          URL Local: http://127.0.0.1:{{ jenkins_internal_port }}/jenkins
          URL Externa: https://jenkins.wd.local/jenkins
          Status Serviço: {{ jenkins_service_status.state }}
          Teste Local: {{ jenkins_local_test.status | default('N/A') }}
          Initial Password: {{ jenkins_initial_password.stdout | default('Configurado via Groovy') }}
          =================================
          📝 PRÓXIMOS PASSOS:
          1. Acesse https://jenkins.wd.local/jenkins
          2. Use usuário: admin
          3. Use a senha definida no secrets.yml

    - name: Coletar logs em caso de problemas
      ansible.builtin.shell:
        cmd: |
          echo "=== Jenkins Service Status ==="
          systemctl status jenkins -l
          echo "=== Jenkins Logs (últimas 50 linhas) ==="
          journalctl -u jenkins -n 50 --no-pager
          echo "=== Jenkins Process ==="
          ps aux | grep jenkins | grep -v grep
          echo "=== Port Check ==="
          netstat -tlnp | grep {{ jenkins_internal_port }} || ss -tlnp | grep {{ jenkins_internal_port }}
        executable: /bin/bash
      register: jenkins_debug_info
      when: jenkins_local_test is failed or jenkins_local_test.status != 200

    - name: Mostrar informações de debug em caso de erro
      ansible.builtin.debug:
        msg: "INFORMAÇÕES DE DEBUG JENKINS:\n{{ jenkins_debug_info.stdout }}"
      when: jenkins_local_test is failed or jenkins_local_test.status != 200

  handlers:
    - name: Reiniciar Jenkins
      ansible.builtin.systemd:
        name: jenkins
        state: restarted
        daemon_reload: yes
      listen: "Reiniciar Jenkins"

```

**What this does:**
- Installs Jenkins with Java 17
- Configures for NGINX reverse proxy
- Sets up initial admin security

#### 5.9 SonarQube Code Quality

playbooks/09_sonarqube_setup.yml

```yaml
# ansible-playbook --ask-vault-pass playbooks/09_sonarqube_setup.yml

- name: Instalar e Configurar SonarQube - LIMPEZA COMPLETA E INSTALAÇÃO
  hosts: sonarqube_server
  become: true
  gather_facts: true

  vars_files:
    - ../group_vars/all.yml
    - ../group_vars/secrets.yml

  tasks:
    - name: Parar todos os serviços relacionados ao SonarQube
      ansible.builtin.systemd:
        name: "{{ item }}"
        state: stopped
        enabled: no
      loop:
        - sonar
        - sonarqube
      ignore_errors: yes

    - name: Remover serviço systemd do SonarQube
      ansible.builtin.file:
        path: /etc/systemd/system/sonar.service
        state: absent
      ignore_errors: yes

    - name: Remover diretório de instalação do SonarQube
      ansible.builtin.file:
        path: /opt/sonarqube
        state: absent

    - name: Remover usuário e grupo sonarqube
      ansible.builtin.user:
        name: sonarqube
        state: absent
        remove: yes
      ignore_errors: yes

    - name: Remover grupo sonarqube
      ansible.builtin.group:
        name: sonarqube
        state: absent
      ignore_errors: yes

    - name: Remover arquivos temporários de download
      ansible.builtin.file:
        path: "{{ item }}"
        state: absent
      loop:
        - "/tmp/sonarqube-{{ sonarqube_version }}.zip"
        - "/tmp/sonarqube-*.zip"

    - name: Limpar banco de dados PostgreSQL
      ansible.builtin.shell: |
        sudo -u postgres psql -c "DROP DATABASE IF EXISTS sonarqube;"
        sudo -u postgres psql -c "DROP USER IF EXISTS sonar;"
      ignore_errors: yes

    - name: Recarregar systemd após limpeza
      ansible.builtin.systemd:
        daemon_reload: yes

    - name: Atualizar cache de pacotes
      ansible.builtin.apt:
        update_cache: yes
        cache_valid_time: 3600

    - name: Instalar Java 17
      ansible.builtin.apt:
        name:
          - openjdk-17-jdk
        state: present

    - name: Verificar instalação do Java
      ansible.builtin.command:
        cmd: java -version
      register: java_check
      changed_when: false

    - name: Instalar PostgreSQL
      ansible.builtin.apt:
        name:
          - postgresql
          - postgresql-contrib
        state: present

    - name: Instalar dependências do sistema
      ansible.builtin.apt:
        name:
          - unzip
          - wget
          - curl
        state: present

    - name: Iniciar e habilitar serviço PostgreSQL
      ansible.builtin.systemd:
        name: postgresql
        state: started
        enabled: true

    - name: Criar usuário de banco de dados
      ansible.builtin.shell:
        cmd: |
          sudo -u postgres psql -c "CREATE USER sonar WITH PASSWORD '{{ sonarqube_db_password }}';"
        executable: /bin/bash
      register: create_user
      changed_when: create_user.rc == 0
      failed_when: create_user.rc != 0

    - name: Criar banco de dados
      ansible.builtin.shell:
        cmd: |
          sudo -u postgres psql -c "CREATE DATABASE sonarqube OWNER sonar;"
        executable: /bin/bash
      register: create_db
      changed_when: create_db.rc == 0
      failed_when: create_db.rc != 0

    - name: Conceder permissões no banco de dados
      ansible.builtin.shell:
        cmd: |
          sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sonarqube TO sonar;"
          sudo -u postgres psql -d sonarqube -c "GRANT CREATE ON SCHEMA public TO sonar;"
          sudo -u postgres psql -d sonarqube -c "GRANT USAGE ON SCHEMA public TO sonar;"
        executable: /bin/bash
      register: grant_perms
      changed_when: grant_perms.rc == 0

    - name: Criar grupo 'sonarqube'
      ansible.builtin.group:
        name: sonarqube
        state: present

    - name: Criar usuário 'sonarqube'
      ansible.builtin.user:
        name: sonarqube
        group: sonarqube
        shell: /bin/bash
        system: yes
        state: present

    - name: Criar estrutura de diretórios do SonarQube
      ansible.builtin.file:
        path: "{{ item }}"
        state: directory
        owner: sonarqube
        group: sonarqube
        mode: '0755'
      loop:
        - /opt/sonarqube
        - /opt/sonarqube/conf
        - /opt/sonarqube/data
        - /opt/sonarqube/temp
        - /opt/sonarqube/logs
        - /opt/sonarqube/extensions

    - name: Baixar SonarQube
      ansible.builtin.command: >
        wget --no-verbose --show-progress
        -O "/tmp/sonarqube-{{ sonarqube_version }}.zip"
        "https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-{{ sonarqube_version }}.zip"
      args:
        creates: "/tmp/sonarqube-{{ sonarqube_version }}.zip"
      register: download_result
      until: download_result is succeeded
      retries: 3
      delay: 10

    - name: Verificar arquivo baixado
      ansible.builtin.stat:
        path: "/tmp/sonarqube-{{ sonarqube_version }}.zip"
      register: downloaded_file

    - name: Descompactar SonarQube para diretório temporário
      ansible.builtin.unarchive:
        src: "/tmp/sonarqube-{{ sonarqube_version }}.zip"
        dest: "/tmp/"
        remote_src: true
        owner: sonarqube
        group: sonarqube
        mode: '0755'
      when: downloaded_file.stat.exists

    - name: Verificar conteúdo descompactado
      ansible.builtin.shell:
        cmd: ls -la /tmp/sonarqube-{{ sonarqube_version }}/
      register: temp_ls_output
      changed_when: false

    - name: Debug - Conteúdo do diretório temporário
      ansible.builtin.debug:
        var: temp_ls_output.stdout

    - name: Mover conteúdo para diretório final (método manual)
      ansible.builtin.shell:
        cmd: |
          # Mover todos os arquivos e subdiretórios para /opt/sonarqube
          cp -r /tmp/sonarqube-{{ sonarqube_version }}/* /opt/sonarqube/
          # Ajustar propriedade de todos os arquivos
          chown -R sonarqube:sonarqube /opt/sonarqube/
          chmod -R 755 /opt/sonarqube/
        executable: /bin/bash
      register: move_content
      changed_when: move_content.rc == 0

    - name: Limpar diretório temporário
      ansible.builtin.file:
        path: "/tmp/sonarqube-{{ sonarqube_version }}"
        state: absent

    - name: Verificar conteúdo final
      ansible.builtin.shell:
        cmd: ls -la /opt/sonarqube/
      register: final_ls_output
      changed_when: false

    - name: Debug - Conteúdo final do diretório
      ansible.builtin.debug:
        var: final_ls_output.stdout

    - name: Configurar arquivo de propriedades
      ansible.builtin.template:
        src: "../templates/sonar.properties.j2"
        dest: /opt/sonarqube/conf/sonar.properties
        owner: sonarqube
        group: sonarqube
        mode: '0644'
      notify: Reiniciar SonarQube

    - name: Verificar e configurar wrapper.conf
      ansible.builtin.stat:
        path: /opt/sonarqube/conf/wrapper.conf
      register: wrapper_conf

    - name: Configurar caminho do Java no wrapper
      ansible.builtin.lineinfile:
        path: /opt/sonarqube/conf/wrapper.conf
        regexp: '^#?wrapper.java.command='
        line: 'wrapper.java.command=/usr/bin/java'
        state: present
        owner: sonarqube
        group: sonarqube
        mode: '0644'
      when: wrapper_conf.stat.exists

    - name: Tornar todos os scripts executáveis
      ansible.builtin.shell:
        cmd: find /opt/sonarqube -name "*.sh" -type f -exec chmod +x {} \;
        executable: /bin/bash
      changed_when: false

    - name: Ajustar limites do sistema
      ansible.builtin.blockinfile:
        path: "/etc/security/limits.conf"
        block: |
          sonarqube   -   nofile   65536
          sonarqube   -   nproc    4096
        marker: "# {mark} ANSIBLE MANAGED BLOCK FOR SONARQUBE LIMITS"

    - name: Configurar limites systemd
      ansible.builtin.blockinfile:
        path: "{{ item }}"
        block: |
          DefaultLimitNOFILE=65536
          DefaultLimitNPROC=4096
        marker: "# {mark} ANSIBLE MANAGED BLOCK FOR SYSTEMD LIMITS"
      loop:
        - "/etc/systemd/system.conf"
        - "/etc/systemd/user.conf"
      notify: Recarregar systemd daemon

    - name: Configurar vm.max_map_count
      ansible.builtin.sysctl:
        name: vm.max_map_count
        value: '262144'
        state: present
        reload: true

    - name: Verificar caminho do script sonar.sh
      ansible.builtin.find:
        paths: /opt/sonarqube
        patterns: "sonar.sh"
        file_type: file
      register: sonar_script

    - name: Debug - Caminho do sonar.sh
      ansible.builtin.debug:
        var: sonar_script.files

    - name: Criar serviço systemd
      ansible.builtin.template:
        src: "../templates/sonar.service.j2"
        dest: /etc/systemd/system/sonar.service
        owner: root
        group: root
        mode: '0644'
      notify:
        - Recarregar systemd daemon
        - Iniciar SonarQube

    - name: Recarregar systemd
      ansible.builtin.systemd:
        daemon_reload: yes

    - name: Iniciar SonarQube
      ansible.builtin.systemd:
        name: sonar
        state: started
        enabled: yes

    - name: Aguardar inicialização do SonarQube
      ansible.builtin.wait_for:
        port: 9000
        host: "127.0.0.1"
        state: started
        timeout: 180
        delay: 10
      register: sonar_port

    - name: Verificar status do serviço
      ansible.builtin.systemd:
        name: sonar
        state: started
      register: service_status

    - name: Testar acesso ao SonarQube
      ansible.builtin.uri:
        url: "http://localhost:9000"
        method: GET
        status_code: 200, 302
        timeout: 30
      register: sonar_test
      when: sonar_port is succeeded

    - name: Mostrar resultado final
      ansible.builtin.debug:
        msg: |
          🎉 SONARQUBE INSTALADO COM SUCESSO!
          ===================================
          URL: http://{{ ansible_host }}:9000
          Status: {{ service_status.state }}
          Teste HTTP: {{ sonar_test.status }}
          ===================================
      when: sonar_port is succeeded

    - name: Coletar logs em caso de falha
      ansible.builtin.shell:
        cmd: journalctl -u sonar -n 30 --no-pager
      register: sonar_logs
      when: sonar_port is failed

    - name: Mostrar logs de erro
      ansible.builtin.debug:
        msg: "LOGS DO SONARQUBE (últimas 30 linhas):\n{{ sonar_logs.stdout }}"
      when: sonar_port is failed

  handlers:
    - name: Recarregar systemd daemon
      ansible.builtin.systemd:
        daemon_reload: true

    - name: Iniciar SonarQube
      ansible.builtin.systemd:
        name: sonar
        state: started
        enabled: true
        daemon_reload: yes

    - name: Reiniciar SonarQube
      ansible.builtin.systemd:
        name: sonar
        state: restarted
        daemon_reload: yes

```

**What this does:**
- Installs SonarQube with PostgreSQL
- Configures analysis parameters
- Sets up service for code quality scanning

#### 5.10 Monitoring Stack

playbooks/10_monitoring_setup.yml

```yaml
ansible-playbook --ask-vault-pass playbooks/10_monitoring_setup.yml

- name: Deploy Prometheus e Grafana com Verificações Robustas
  hosts: k3s_master
  become: yes

  tasks:
    - name: Carregar variáveis de secrets.yml (se existir)
      ansible.builtin.include_vars:
        file: group_vars/secrets.yml
      failed_when: false
      ignore_errors: yes

    - name: Definir senha padrão se não foi carregada
      ansible.builtin.set_fact:
        grafana_admin_password: "Admin@123456"
      when: grafana_admin_password is not defined

    - name: Exibir aviso sobre senha
      ansible.builtin.debug:
        msg: "⚠️ Usando senha padrão. Para produção, crie group_vars/secrets.yml com senha personalizada."
      when: grafana_admin_password == "Admin@123456"

    - name: Verificar se k3s está em execução
      ansible.builtin.systemd:
        name: k3s
        state: started
      check_mode: yes
      register: k3s_status
      failed_when: false

    - name: Falhar se k3s não estiver rodando
      ansible.builtin.fail:
        msg: "Cluster k3s não está em execução. Inicie o k3s antes de prosseguir."
      when: k3s_status.status.ActiveState != "active"

    - name: Verificar se Helm está instalado
      ansible.builtin.command: helm version --short
      register: helm_check
      changed_when: false
      failed_when: false

    - name: Falhar se Helm não estiver instalado
      ansible.builtin.fail:
        msg: "Helm não encontrado. Instale o Helm antes de prosseguir."
      when: helm_check.rc != 0

    - name: Verificar biblioteca kubernetes do Python
      ansible.builtin.command: python3 -c "import kubernetes"
      register: python_k8s_check
      changed_when: false
      failed_when: false

    - name: Instalar biblioteca kubernetes se ausente
      ansible.builtin.pip:
        name: kubernetes
        executable: pip3
        state: present
      when: python_k8s_check.rc != 0

    - name: Verificar se namespace monitoring já existe
      kubernetes.core.k8s_info:
        kind: Namespace
        name: monitoring
        kubeconfig: /etc/rancher/k3s/k3s.yaml
      register: namespace_check
      failed_when: false

    - name: Definir namespace_exists como false por padrão
      ansible.builtin.set_fact:
        namespace_exists: false

    - name: Atualizar namespace_exists se encontrado
      ansible.builtin.set_fact:
        namespace_exists: true
      when:
        - namespace_check.resources is

```

**What this does:**
- Deploys Prometheus stack to Kubernetes
- Configures Grafana with dashboards
- Sets up Alertmanager for notifications

**All Ansible templates files are available in the repository**

---

## ✅ INFRASTRUCTURE VERIFICATION

### 🔍 STEP 6: Service Verification

#### 6.1 Access All Services
After all playbooks complete successfully, access each service:

- **📊 Dashboard**: https://dashboard.wd.local
- **📦 GitLab**: https://gitlab.wd.local
- **🐄 Rancher**: https://rancher.wd.local
- **⚙️ Jenkins**: https://jenkins.wd.local/jenkins
- **🔍 SonarQube**: https://sonarqube.wd.local
- **📈 Grafana**: https://grafana.wd.local
- **🔄 ArgoCD**: https://argocd.wd.local

#### 6.2 Kubernetes Verification

**K3s cluster verification:**
```bash
# Verify cluster nodes
kubectl get nodes

# Verify all pods are running
kubectl get pods --all-namespaces

# Verify GitLab Runner registration
kubectl get pods -n gitlab-runner
```

#### 6.3 SSL Certificate Verification

**SSL verification:**
```bash
# Check certificate chain
openssl s_client -connect gitlab.wd.local:443 -showcerts

# Verify certificate trust
curl -I https://gitlab.wd.local
```

---

## 🐛 TROUBLESHOOTING

### ❗ COMMON ISSUES AND SOLUTIONS

#### 7.1 DNS Resolution Problems
**Symptoms**: Services cannot resolve each other's hostnames
**Solution**: Verify Windows DNS records and /etc/hosts entries on all VMs

#### 7.2 SSL Certificate Issues
**Symptoms**: Browser SSL warnings or curl certificate errors
**Solution**: Ensure Root CA is properly distributed to all systems

#### 7.3 GitLab Runner Registration
**Symptoms**: Runner doesn't appear in GitLab admin interface
**Solution**: Check runner logs and verify registration token

#### 7.4 Kubernetes Pod Issues
**Symptoms**: Pods stuck in pending or crash loop backoff
**Solution**: Check resource limits and node capacity

### 📋 LOG LOCATIONS
- **NGINX**: `/var/log/nginx/`
- **GitLab**: `sudo gitlab-ctl tail`
- **K3s**: `journalctl -u k3s`
- **Kubernetes Pods**: `kubectl logs <pod-name> -n <namespace>`

---

## PART 2: APPLICATION PIPELINE & GITOPS

*Now that our base infrastructure is established, let's deploy a sample application to validate the complete DevOps workflow.*

---

## 📂 PROJECT SETUP & GIT REPOSITORIES

### 1.1. 🚀 APPLICATION REPOSITORY (wd-nodejs-docker)

#### 📝 Create GitLab Project
1. **Navigate to GitLab UI** → "New Project"
2. **Project Name**: `wd-nodejs-docker`
3. **Clone repository locally**:
   ```bash
   git clone https://gitlab.wd.local/wagner/wd-nodejs-docker.git
   cd wd-nodejs-docker
   ```

#### 📄 Application Files Structure

**🚀 app.js** (Node.js Express Application)
```javascript
const express = require('express');
const app = express();
const port = process.env.PORT || 8080;
const appName = process.env.APP_NAME || 'Default App';
const appVersion = process.env.APP_VERSION || '1.0.0';

app.get('/', (req, res) => {
  res.send(`Hello from ${appName} v${appVersion}!`);
});

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.listen(port, '0.0.0.0', () => {
  console.log(`${appName} v${appVersion} listening on port ${port}`);
});
```

**📦 package.json** (Dependencies & Scripts)
```json
{
  "name": "wd-nodejs-docker",
  "version": "1.0.0",
  "description": "A simple Node.js app for DevOps demo",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "start-dev": "nodemon app.js",
    "test": "echo \"No tests specified\" && exit 0"
  },
  "dependencies": {
    "express": "^4.18.2"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
```

**🐳 Dockerfile** (Containerization)
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 8080
CMD ["npm", "start"]
```

**🔍 sonar-project.properties** (Code Analysis Configuration)
```ini
sonar.projectKey=wd-nodejs-docker
sonar.projectName=wd-nodejs-docker
sonar.projectVersion=1.0
sonar.sources=.
sonar.exclusions=node_modules/**
sonar.tests=.
sonar.test.inclusions=**/*.test.js,**/*.spec.js
sonar.javascript.lcov.reportPaths=coverage/lcov.info
```

#### 💾 Initial Commit
```bash
git add .
git commit -m "Initial Node.js application"
git push origin main
```

### 1.2. 🔄 GITOPS REPOSITORY (gitops-repo)

#### 📝 Create GitLab Project
1. **Navigate to GitLab UI** → "New Project"
2. **Project Name**: `gitops-repo`
3. **Ensure user `wagner` has write permissions**
4. **Clone repository locally**:
   ```bash
   git clone https://gitlab.wd.local/wagner/gitops-repo.git
   cd gitops-repo
   ```

#### ☸️ Kubernetes Manifests

**📋 kubernetes/deployment.yaml**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wd-nodejs-docker-deployment
  namespace: wd-app-env
  labels:
    app: wd-nodejs-docker
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wd-nodejs-docker
  template:
    metadata:
      labels:
        app: wd-nodejs-docker
    spec:
      imagePullSecrets:
      - name: gitlab-registry-secret
      containers:
      - name: wd-nodejs-docker
        image: gitlab.wd.local/wagner/wd-nodejs-docker:latest
        ports:
        - containerPort: 8080
        env:
        - name: APP_NAME
          value: "DevOpsGuru Sample App"
        - name: APP_VERSION
          value: "1.0.0"
        - name: PORT
          value: "8080"
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 15
          periodSeconds: 10
          timeoutSeconds: 3
---
apiVersion: v1
kind: Service
metadata:
  name: wd-nodejs-docker-service
  namespace: wd-app-env
  labels:
    app: wd-nodejs-docker
spec:
  selector:
    app: wd-nodejs-docker
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
  type: NodePort
```

#### 💾 Initial Commit
```bash
git add .
git commit -m "Initial Kubernetes manifests"
git push origin main
```

---

## 🔄 GITLAB CI/CD PIPELINE

### 2.1. ⚙️ .gitlab-ci.yml Configuration

**🔧 .gitlab-ci.yml** (Complete Pipeline Definition)
```yaml
stages:
  - build
  - test
  - security
  - deploy-gitops

variables:
  DOCKER_IMAGE_NAME: gitlab.wd.local/wagner/wd-nodejs-docker
  DOCKER_IMAGE_TAG: $CI_COMMIT_SHORT_SHA
  GIT_STRATEGY: clone
  KUBERNETES_NAMESPACE: wd-app-env

# --- 🐳 Build Stage ---
build-docker-image:
  stage: build
  image:
    name: gcr.io/kaniko-project/executor:v1.9.0-debug
    entrypoint: [""]
  before_script:
    - echo "Building Docker image with Kaniko..."
    - mkdir -p /kaniko/.docker
  script:
    - /kaniko/executor
      --context "${CI_PROJECT_DIR}"
      --dockerfile "${CI_PROJECT_DIR}/Dockerfile"
      --destination "${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"
      --destination "${DOCKER_IMAGE_NAME}:latest"
      --skip-tls-verify=true
      --verbosity=info
    - echo "Image pushed: ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"
  tags:
    - kubernetes
  only:
    - main

# --- 🧪 Test Stage ---
unit-integration-tests:
  stage: test
  image: node:18-alpine
  script:
    - echo "Running unit and integration tests..."
    - npm install
    - npm test
  artifacts:
    paths:
      - coverage/lcov.info
    reports:
      junit: junit.xml
  tags:
    - kubernetes
  only:
    - main

# —- 🔒 Security Stage —-
sonarqube-analysis:
  stage: security
  image: sonarsource/sonar-scanner-cli:latest
  variables:
    SONAR_HOST_URL: "https://sonarqube.wd.local"
    SONAR_TOKEN: "$SONAR_TOKEN"
    SONAR_PROJECT_KEY: "wd-nodejs-docker"
    SONAR_SOURCES: "."
    SONAR_BRANCH: "$CI_COMMIT_REF_NAME"
  script:
    - echo "Running SonarQube analysis..."
    - >
      sonar-scanner
      -Dsonar.projectKey=$SONAR_PROJECT_KEY
      -Dsonar.projectName=$SONAR_PROJECT_KEY
      -Dsonar.sources=$SONAR_SOURCES
      -Dsonar.host.url=$SONAR_HOST_URL
      -Dsonar.login=$SONAR_TOKEN
      -Dsonar.branch.name=$SONAR_BRANCH
      -Dsonar.javascript.lcov.reportPaths=coverage/lcov.info
  allow_failure: false
  tags:
    - kubernetes
  only:
    - main

# —- 🚀 Deploy-GitOps Stage —-
update-gitops-repo:
  stage: deploy-gitops
  image: alpine/git:latest
  before_script:
    - git config user.name "GitLab CI/CD"
    - git config user.email "gitlab-ci@wd.local"
    - apk add --no-cache yq
  script:
    - echo "Cloning GitOps repository..."
    - git clone https://oauth2:$GITLAB_TOKEN@gitlab.wd.local/wagner/gitops-repo.git
    - cd gitops-repo
    - echo "Updating image tag in kubernetes/deployment.yaml to ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}..."
    - yq eval ".spec.template.spec.containers[0].image = \"${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}\"" -i kubernetes/deployment.yaml
    - echo "Updated deployment.yaml content:"
    - cat kubernetes/deployment.yaml | grep image:
    - git add kubernetes/deployment.yaml
    - git commit -m "CI/CD: Update image to ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"
    - git push origin main
  variables:
    GITLAB_TOKEN: $GITLAB_TOKEN
  tags:
    - kubernetes
  only:
    - main
```

### 2.2. 🔑 CI/CD VARIABLES CONFIGURATION

#### ⚙️ GitLab CI/CD Variables Setup
1. **Navigate to**: Project → Settings → CI/CD → Variables
2. **Add the following variables**:

| Variable | Value | Protection | Masking |
|----------|-------|------------|---------|
| `GITLAB_TOKEN` | GitLab Personal Access Token | ✅ Protected | ✅ Masked |
| `SONAR_TOKEN` | SonarQube User Token | ✅ Protected | ✅ Masked |

#### 🔐 Creating Required Tokens

**GitLab Personal Access Token**:
1. **User Settings** → **Access Tokens**
2. **Token Name**: `gitlab-ci-token`
3. **Scopes**: `write_repository`, `read_registry`
4. **Expiration**: Set appropriate expiration
5. **Copy token** and add to CI/CD variables as `GITLAB_TOKEN`

**SonarQube Token**:
1. **SonarQube UI** → **User Icon** → **My Account** → **Security**
2. **Generate Tokens**
3. **Token Name**: `gitlab-integration`
4. **Copy token** and add to CI/CD variables as `SONAR_TOKEN`

---

## ☸️ KUBERNETES & ARGOCD CONFIGURATION

### 3.1. 🏗️ KUBERNETES SETUP

#### 📁 Create Application Namespace
```bash
# Connect to k3s-master via SSH
ssh k3s-master

# Create application namespace
kubectl create namespace wd-app-env
```

#### 🔐 Create Image Pull Secret
```bash
kubectl create secret docker-registry gitlab-registry-secret \
  --docker-server=gitlab.wd.local:443 \
  --docker-username=wagner \
  --docker-password=glpat-xxxxxxxxxxxxxxxx \
  --docker-email=wagner@wd.local \
  -n wd-app-env
```

#### ✅ Verify Secret Creation
```bash
kubectl get secrets -n wd-app-env
```

### 3.2. 🔄 ARGOCD APPLICATION CONFIGURATION

#### 🖥️ ArgoCD UI Setup
1. **Access ArgoCD**: `https://argocd.wd.local`
2. **Login** with admin credentials

#### ➕ Create New Application
- **Application Name**: `wd-nodejs-docker`
- **Project**: `default`
- **Sync Policy**: 
  - ✅ **Automatic**
  - ✅ **Prune Resources**
  - ✅ **Self Heal**

#### 📂 Source Configuration
- **Repository URL**: `https://gitlab.wd.local/wagner/gitops-repo.git`
- **Revision**: `HEAD`
- **Path**: `kubernetes`

#### 🎯 Destination Configuration
- **Cluster**: `in-cluster` (`https://kubernetes.default.svc`)
- **Namespace**: `wd-app-env`

#### 🚀 Create & Sync
- Click **"CREATE"**
- ArgoCD will automatically detect and sync the application
- Monitor sync status in ArgoCD dashboard

---

## 📊 MONITORING & ALERTING

### 5.1. 🚨 ALERTMANAGER CONFIGURATION

#### 🔍 Access Alertmanager
```bash
# Get Alertmanager NodePort
kubectl get svc prometheus-kube-prometheus-alertmanager -n monitoring -o jsonpath='{.spec.ports[?(@.name=="web")].nodePort}'

# Access via: http://192.168.204.150:<NODEPORT_ALERTMANAGER>
```

#### ⚙️ Configure Teams/Slack Notifications
```bash
# Edit Alertmanager configuration
kubectl edit configmap prometheus-kube-prometheus-alertmanager -n monitoring
```

**Add to configuration**:
```yaml
alertmanager.yaml: |
  global:
    resolve_timeout: 5m
  route:
    group_by: ['alertname', 'cluster', 'service']
    group_wait: 30s
    group_interval: 5m
    repeat_interval: 12h
    receiver: 'default-receiver'
    routes:
    - match:
        severity: critical
      receiver: 'teams-webhook'
  receivers:
  - name: 'default-receiver'
  - name: 'teams-webhook'
    webhook_configs:
    - send_resolved: true
      url: 'https://outlook.office.com/webhook/YOUR_TEAMS_WEBHOOK_URL'
```

### 5.2. ⚠️ CUSTOM ALERT RULES

**🚨 app-alerts.yaml** (Application Health Alerts)
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: app-health-alerts
  namespace: monitoring
  labels:
    prometheus: k8s
    role: alert-rules
spec:
  groups:
  - name: application-health
    rules:
    - alert: ApplicationDown
      expr: sum(up{job="kubernetes-pods", namespace="wd-app-env", app="wd-nodejs-docker"}) == 0
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "Application {{ $labels.app }} is down in namespace {{ $labels.namespace }}"
        description: "All pods for application {{ $labels.app }} in namespace {{ $labels.namespace }} have been down for more than 5 minutes."
    - alert: PodCrashing
      expr: sum(changes(kube_pod_container_status_restarts_total{namespace="wd-app-env", app="wd-nodejs-docker"}[5m])) > 0
      for: 1m
      labels:
        severity: warning
      annotations:
        summary: "Application {{ $labels.app }} pod is crashing in namespace {{ $labels.namespace }}"
        description: "A pod for application {{ $labels.app }} in namespace {{ $labels.namespace }} has recently restarted."
```

#### 📥 Apply Alert Rules
```bash
kubectl apply -f app-alerts.yaml
```

---

## 🔄 FAILURE RECOVERY & ROLLBACK

### 6.1. 🚨 FAILURE SCENARIOS & RECOVERY

#### ⚠️ CI/CD Pipeline Failures
- **Test Failures**: Pipeline stops, developer notification
- **Build Failures**: Kaniko build issues, image push failures
- **Security Violations**: SonarQube quality gate failures
- **GitOps Update Failures**: Permission or repository access issues

#### ⚠️ ArgoCD Sync Failures
- **Manifest Errors**: YAML syntax, Kubernetes validation
- **Resource Conflicts**: Existing resource modifications
- **Network Issues**: Repository access, cluster connectivity

#### ⚠️ Runtime Failures
- **CrashLoopBackOff**: Application startup issues
- **Health Check Failures**: Readiness/liveness probe timeouts
- **Resource Exhaustion**: CPU/Memory limits exceeded

### 6.2. ↩️ ROLLBACK STRATEGIES

#### 🔄 GitOps Rollback (Recommended)
```bash
# Identify problematic commit
cd gitops-repo
git log --oneline

# Revert to previous stable commit
git revert <SHA_OF_PROBLEMATIC_COMMIT>
git push origin main

# ArgoCD automatically syncs to previous version
```

#### ⚡ Manual Kubernetes Rollback
```bash
# Quick emergency rollback
kubectl rollout undo deployment/wd-nodejs-docker-deployment -n wd-app-env

# Check rollback status
kubectl rollout status deployment/wd-nodejs-docker-deployment -n wd-app-env
```

### 6.3. 📢 AUTOMATED NOTIFICATIONS

#### 🔔 GitLab Pipeline Notifications
1. **Project Settings** → **Integrations**
2. **Add Microsoft Teams/Slack Webhook**
3. **Configure Events**:
   - ✅ Pipeline successes
   - ✅ Pipeline failures
   - ✅ Deployment events

#### 🚨 Alertmanager Notifications
- **Critical Alerts**: Immediate notification
- **Warning Alerts**: Daily digest
- **Resolved Alerts**: Confirmation notifications

---

## 💻 LOCAL DEVELOPMENT ENVIRONMENT

### 7.1. 🐳 DOCKER COMPOSE SETUP

**🔧 docker-compose.yml** (Local Development)
```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      APP_NAME: "Local Dev App"
      APP_VERSION: "1.0.0-local"
      PORT: 8080
    volumes:
      - .:/app
      - /app/node_modules
    command: npm run start-dev
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  db_data:
```

#### 🚀 Start Local Development
```bash
# Build and start services
docker-compose up --build

# Access application: http://localhost:8080
```

#### 📦 Package.json Development Script
```json
{
  "scripts": {
    "start-dev": "nodemon app.js"
  }
}
```

---

## ✅ COMPREHENSIVE VERIFICATION

### 8.1. 📋 COMPREHENSIVE VERIFICATION CHECKLIST

#### 🌐 DNS & Web Access Verification
```bash
# Verify DNS resolution
nslookup gitlab.wd.local
nslookup rancher.wd.local
nslookup sonarqube.wd.local

# Test web access (all should work with SSL)
https://dashboard.wd.local
https://gitlab.wd.local
https://rancher.wd.local
https://sonarqube.wd.local
https://jenkins.wd.local/jenkins/
https://grafana.wd.local
https://argocd.wd.local
```

#### 🛠️ SERVICE-SPECIFIC VERIFICATION

**Nginx Verification**:
```bash
sudo nginx -t                    # Test configuration
sudo systemctl status nginx      # Check service status
sudo tail -f /var/log/nginx/access.log  # Monitor access logs
sudo tail -f /var/log/nginx/error.log   # Monitor error logs
```

**GitLab Verification**:
```bash
sudo gitlab-ctl status          # All services status
sudo gitlab-ctl tail            # Real-time logs
sudo gitlab-rake gitlab:check   # Health check
```

**K3s Verification**:
```bash
kubectl get nodes              # Cluster nodes
kubectl get pods --all-namespaces  # All pods
kubectl get svc -n wd-app-env  # Application services
```

**ArgoCD Verification**:
```bash
kubectl get application -n argocd  # Application status
argocd app sync wd-nodejs-docker   # Manual sync
```

### 8.2. 🐛 COMMON ISSUES & SOLUTIONS

#### 🔒 Certificate Issues
**Symptoms**: Browser SSL warnings, connection failures
**Solutions**:
```bash
# Verify certificate installation
openssl s_client -connect gitlab.wd.local:443 -servername gitlab.wd.local

# Check CA distribution
sudo update-ca-certificates
ls -la /usr/local/share/ca-certificates/
```

#### 🐳 ImagePullBackOff Errors
**Symptoms**: Pods stuck in ImagePullBackOff state
**Solutions**:
```bash
# Check registry configuration
cat /etc/rancher/k3s/registries.yaml

# Verify image pull secret
kubectl describe pod -n wd-app-env <pod-name>

# Check PAT permissions
kubectl get secrets -n wd-app-env gitlab-registry-secret -o yaml
```

#### 🔄 CrashLoopBackOff Errors
**Symptoms**: Pods restarting continuously
**Solutions**:
```bash
# Check application logs
kubectl logs -n wd-app-env <pod-name> --previous

# Verify health checks
kubectl describe deployment -n wd-app-env wd-nodejs-docker-deployment

# Test application locally
docker-compose up --build
```

#### ⚙️ Pipeline Failures
**Symptoms**: CI/CD jobs failing
**Solutions**:
- Check job logs in GitLab UI
- Verify CI/CD variables are set correctly
- Test `yq` commands locally
- Check GitLab token permissions

#### 🔄 ArgoCD Sync Issues
**Symptoms**: Application out of sync, sync failures
**Solutions**:
```bash
# Check application details
kubectl get application -n argocd wd-nodejs-docker -o yaml

# Check controller logs
kubectl logs -n argocd deployment/argocd-application-controller -f

# Manual sync
argocd app sync wd-nodejs-docker
```

### 8.3. 🧪 APPLICATION ACCESS TESTING

#### 🔌 Test NodePort Access
```bash
# Get NodePort for application
kubectl get svc -n wd-app-env wd-nodejs-docker-service

# Test application access
curl http://192.168.204.150:<NODEPORT>
```

#### ❤️ Health Check Verification
```bash
# Test health endpoint
curl http://192.168.204.150:<NODEPORT>/health

# Check pod status
kubectl get pods -n wd-app-env -w
```

---

## 🎉 SUCCESS INDICATORS

- ✅ **Pipeline completes** all stages successfully
- ✅ **ArgoCD shows** Synced and Healthy status
- ✅ **Application responds** on health checks
- ✅ **No critical alerts** in Prometheus
- ✅ **Code quality gates** passed in SonarQube
- ✅ **All services accessible** via web UI with SSL

## 🆘 EMERGENCY CONTACTS

- **GitLab Issues**: Check pipeline logs and job artifacts
- **Kubernetes Issues**: Use `kubectl describe` and `kubectl logs`
- **ArgoCD Issues**: Check application sync status and controller logs
- **Network Issues**: Verify DNS resolution and certificate validity

---

## 📋 FINAL CHECKLIST & NEXT STEPS

### ✅ FINAL CHECKLIST
- [ ] All VMs created and networked properly
- [ ] DNS resolution working for all services
- [ ] SSL certificates trusted across all systems
- [ ] GitLab accessible with initial setup complete
- [ ] K3s cluster with all nodes ready
- [ ] All services accessible via NGINX reverse proxy
- [ ] GitLab Runner registered and online
- [ ] Monitoring stack deployed and accessible
- [ ] Application pipeline working end-to-end
- [ ] ArgoCD syncing application successfully

### 🚀 NEXT STEPS
1. **Configure GitLab Projects**: Set up your first repository and CI/CD pipeline
2. **Setup ArgoCD Applications**: Define your first GitOps application
3. **Configure Monitoring